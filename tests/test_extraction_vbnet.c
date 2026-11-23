/*
 * test_extraction_vbnet.c — VB.NET routed to the vendored vbnet grammar.
 *
 * The fixtures are invented: a Web API 2 controller, a Module, a Structure
 * and an Interface. The extraction cases check definitions, calls, imports
 * and the attribute route; the pipeline case indexes two files and checks
 * that calls written in another letter case still become CALLS edges, since
 * VB.NET names are case-insensitive.
 */
#include "test_framework.h"
#include "test_helpers.h"
#include "cbm.h"
#include "../src/foundation/compat.h"
#include "../src/foundation/compat_fs.h"
#include <mcp/mcp.h>
#include <store/store.h>
#include <pipeline/pipeline.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char VB_CONTROLLER[] =
    "Imports System.Web.Http\n"
    "Imports Demo.Services\n"
    "\n"
    "Namespace Demo.Api\n"
    "    <RoutePrefix(\"api/cuentas\")>\n"
    "    Public Class CuentasController\n"
    "        Inherits ApiController\n"
    "        Implements IDisposable\n"
    "\n"
    "        Private _svc As CuentaService\n"
    "\n"
    "        Public Sub New()\n"
    "            _svc = New CuentaService()\n"
    "        End Sub\n"
    "\n"
    "        <Route(\"api/cuentas/abrir\")>\n"
    "        <HttpPost>\n"
    "        Public Function Abrir(ByVal req As String) As IHttpActionResult\n"
    "            Dim r = _svc.validar(req)\n"
    "            helper.registrar(req)\n"
    "            Return Ok(r)\n"
    "        End Function\n"
    "\n"
    "        Public Sub Dispose() Implements IDisposable.Dispose\n"
    "        End Sub\n"
    "    End Class\n"
    "\n"
    "    Public Module Helper\n"
    "        Public Sub Registrar(s As String)\n"
    "            Console.WriteLine(s)\n"
    "        End Sub\n"
    "    End Module\n"
    "End Namespace\n";

static const char VB_SERVICE[] =
    "Namespace Demo.Services\n"
    "    Public Interface IServicio\n"
    "        Function Validar(s As String) As Boolean\n"
    "    End Interface\n"
    "\n"
    "    Public Structure Punto\n"
    "        Public X As Integer\n"
    "    End Structure\n"
    "\n"
    "    Public Class CuentaService\n"
    "        Implements IServicio\n"
    "\n"
    "        Public Function Validar(s As String) As Boolean Implements IServicio.Validar\n"
    "            Return Normalizar(s) <> \"\"\n"
    "        End Function\n"
    "\n"
    "        Private Function Normalizar(s As String) As String\n"
    "            Return s.Trim()\n"
    "        End Function\n"
    "    End Class\n"
    "End Namespace\n";

static CBMFileResult *extract_vb(const char *src, const char *path) {
    return cbm_extract_file(src, (int)strlen(src), CBM_LANG_VBNET, "t", path, 0, NULL, NULL);
}

static const CBMDefinition *find_def(const CBMFileResult *r, const char *label, const char *name) {
    for (int i = 0; i < r->defs.count; i++) {
        const CBMDefinition *d = &r->defs.items[i];
        if (strcmp(d->label, label) == 0 && strcmp(d->name, name) == 0) {
            return d;
        }
    }
    return NULL;
}

static int has_callee(const CBMFileResult *r, const char *callee) {
    for (int i = 0; i < r->calls.count; i++) {
        if (strcmp(r->calls.items[i].callee_name, callee) == 0) {
            return 1;
        }
    }
    return 0;
}

static int has_import(const CBMFileResult *r, const char *module_path) {
    for (int i = 0; i < r->imports.count; i++) {
        const char *p = r->imports.items[i].module_path;
        if (p && strcmp(p, module_path) == 0) {
            return 1;
        }
    }
    return 0;
}

static int has_base(const CBMDefinition *d, const char *base) {
    for (const char **b = d ? d->base_classes : NULL; b && *b; b++) {
        if (strcmp(*b, base) == 0) {
            return 1;
        }
    }
    return 0;
}

TEST(vbnet_definitions) {
    CBMFileResult *r = extract_vb(VB_CONTROLLER, "Api/CuentasController.vb");
    ASSERT_NOT_NULL(r);
    const CBMDefinition *cls = find_def(r, "Class", "CuentasController");
    ASSERT_NOT_NULL(cls);
    ASSERT_TRUE(has_base(cls, "ApiController"));
    ASSERT_TRUE(has_base(cls, "IDisposable"));
    ASSERT_NOT_NULL(find_def(r, "Method", "Abrir"));
    ASSERT_NOT_NULL(find_def(r, "Method", "Dispose"));
    ASSERT_NOT_NULL(find_def(r, "Method", "New"));
    ASSERT_NOT_NULL(find_def(r, "Class", "Helper"));
    ASSERT_NOT_NULL(find_def(r, "Method", "Registrar"));
    cbm_free_result(r);

    r = extract_vb(VB_SERVICE, "Services/CuentaService.vb");
    ASSERT_NOT_NULL(r);
    ASSERT_NOT_NULL(find_def(r, "Interface", "IServicio"));
    ASSERT_NOT_NULL(find_def(r, "Class", "CuentaService"));
    ASSERT_NOT_NULL(find_def(r, "Method", "Validar"));
    ASSERT_NOT_NULL(find_def(r, "Method", "Normalizar"));
    ASSERT_TRUE(find_def(r, "Struct", "Punto") || find_def(r, "Class", "Punto"));
    cbm_free_result(r);
    PASS();
}

TEST(vbnet_calls_imports_route) {
    CBMFileResult *r = extract_vb(VB_CONTROLLER, "Api/CuentasController.vb");
    ASSERT_NOT_NULL(r);
    /* `x.f(a)` parses as an index expression in VB.NET; it is still a call. */
    ASSERT_TRUE(has_callee(r, "_svc.validar"));
    ASSERT_TRUE(has_callee(r, "helper.registrar"));
    ASSERT_TRUE(has_callee(r, "Console.WriteLine"));
    ASSERT_TRUE(has_callee(r, "CuentaService"));
    ASSERT_TRUE(has_import(r, "System.Web.Http"));
    ASSERT_TRUE(has_import(r, "Demo.Services"));
    const CBMDefinition *abrir = find_def(r, "Method", "Abrir");
    ASSERT_NOT_NULL(abrir);
    ASSERT_NOT_NULL(abrir->route_path);
    ASSERT_STR_EQ(abrir->route_path, "/api/cuentas/abrir");
    ASSERT_STR_EQ(abrir->route_method, "POST");
    cbm_free_result(r);
    PASS();
}

/* ── Pipeline ──────────────────────────────────────────────────── */

typedef struct {
    char tmpdir[256];
    char dbpath[512];
    char *project;
    cbm_mcp_server_t *srv;
    cbm_store_t *store;
} VbProj;

static bool vb_index(VbProj *p) {
    memset(p, 0, sizeof(*p));
    snprintf(p->tmpdir, sizeof(p->tmpdir), "/tmp/cbm_vbnet_XXXXXX");
    if (!cbm_mkdtemp(p->tmpdir)) {
        return false;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/Api", p->tmpdir);
    cbm_mkdir_p(path, 0755);
    snprintf(path, sizeof(path), "%s/Services", p->tmpdir);
    cbm_mkdir_p(path, 0755);
    snprintf(path, sizeof(path), "%s/Api/CuentasController.vb", p->tmpdir);
    if (th_write_file(path, VB_CONTROLLER) != 0) {
        return false;
    }
    snprintf(path, sizeof(path), "%s/Services/CuentaService.vb", p->tmpdir);
    if (th_write_file(path, VB_SERVICE) != 0) {
        return false;
    }
    p->project = cbm_project_name_from_path(p->tmpdir);
    if (!p->project) {
        return false;
    }
    const char *home = getenv("HOME");
    char cache_dir[512];
    snprintf(cache_dir, sizeof(cache_dir), "%s/.cache/codebase-memory-mcp", home ? home : "/tmp");
    cbm_mkdir(cache_dir);
    snprintf(p->dbpath, sizeof(p->dbpath), "%s/%s.db", cache_dir, p->project);
    unlink(p->dbpath);
    p->srv = cbm_mcp_server_new(NULL);
    if (!p->srv) {
        return false;
    }
    char args[700];
    snprintf(args, sizeof(args), "{\"repo_path\":\"%s\"}", p->tmpdir);
    free(cbm_mcp_handle_tool(p->srv, "index_repository", args));
    p->store = cbm_store_open_path(p->dbpath);
    return p->store != NULL;
}

static void vb_cleanup(VbProj *p) {
    if (p->store) {
        cbm_store_close(p->store);
    }
    if (p->srv) {
        cbm_mcp_server_free(p->srv);
    }
    free(p->project);
    th_rmtree(p->tmpdir);
    unlink(p->dbpath);
    char side[600];
    snprintf(side, sizeof(side), "%s-wal", p->dbpath);
    unlink(side);
    snprintf(side, sizeof(side), "%s-shm", p->dbpath);
    unlink(side);
}

/* An edge of `type` whose source QN ends with src_suffix and target QN ends
 * with tgt_suffix. */
static int vb_edge(cbm_store_t *store, const char *project, const char *type,
                   const char *src_suffix, const char *tgt_suffix) {
    cbm_edge_t *edges = NULL;
    int n = 0;
    if (cbm_store_find_edges_by_type(store, project, type, &edges, &n) != CBM_STORE_OK) {
        return 0;
    }
    int found = 0;
    size_t ssl = strlen(src_suffix);
    size_t tsl = strlen(tgt_suffix);
    for (int i = 0; i < n && !found; i++) {
        cbm_node_t src;
        cbm_node_t tgt;
        if (cbm_store_find_node_by_id(store, edges[i].source_id, &src) != CBM_STORE_OK) {
            continue;
        }
        if (cbm_store_find_node_by_id(store, edges[i].target_id, &tgt) != CBM_STORE_OK) {
            cbm_node_free_fields(&src);
            continue;
        }
        const char *sq = src.qualified_name;
        const char *tq = tgt.qualified_name;
        if (sq && tq) {
            size_t sql = strlen(sq);
            size_t tql = strlen(tq);
            found = sql >= ssl && strcmp(sq + sql - ssl, src_suffix) == 0 && tql >= tsl &&
                    strcmp(tq + tql - tsl, tgt_suffix) == 0;
        }
        cbm_node_free_fields(&src);
        cbm_node_free_fields(&tgt);
    }
    cbm_store_free_edges(edges, n);
    return found;
}

/* `helper.registrar(req)` reaches Helper.Registrar in the same file and
 * `_svc.validar(req)` reaches CuentaService.Validar in another one; inside
 * CuentaService the unqualified Normalizar call resolves as written, and
 * `Implements IServicio` becomes an IMPLEMENTS edge. */
TEST(vbnet_pipeline_resolves_case_insensitive_calls) {
    VbProj p;
    bool ok = vb_index(&p);
    int to_registrar = 0;
    int to_validar = 0;
    int to_normalizar = 0;
    int routes = 0;
    int implements = 0;
    if (ok) {
        implements = vb_edge(p.store, p.project, "IMPLEMENTS", "CuentaService", "IServicio");
        to_registrar =
            vb_edge(p.store, p.project, "CALLS", "CuentasController.Abrir", "Helper.Registrar");
        to_validar = vb_edge(p.store, p.project, "CALLS", "CuentasController.Abrir",
                             "CuentaService.Validar");
        to_normalizar = vb_edge(p.store, p.project, "CALLS", "CuentaService.Validar",
                                "CuentaService.Normalizar");
        cbm_node_t *nodes = NULL;
        if (cbm_store_find_nodes_by_label(p.store, p.project, "Route", &nodes, &routes) ==
            CBM_STORE_OK) {
            cbm_store_free_nodes(nodes, routes);
        }
    }
    vb_cleanup(&p);
    ASSERT_TRUE(ok);
    ASSERT_TRUE(to_normalizar);
    ASSERT_TRUE(to_registrar);
    ASSERT_TRUE(to_validar);
    ASSERT_GTE(routes, 1);
    ASSERT_TRUE(implements);
    PASS();
}

SUITE(extraction_vbnet) {
    RUN_TEST(vbnet_definitions);
    RUN_TEST(vbnet_calls_imports_route);
    RUN_TEST(vbnet_pipeline_resolves_case_insensitive_calls);
}
