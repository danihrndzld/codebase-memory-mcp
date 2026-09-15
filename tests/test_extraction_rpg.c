/*
 * test_extraction_rpg.c — IBM i RPG extractor (internal/cbm/extract_rpg.c).
 *
 * Fixed-form fixtures are assembled by column helpers (d_spec, c_spec, ...)
 * so a field never lands in the wrong column through hand-counted blanks; the
 * free-form fixtures are written as source. The last test indexes two members
 * through the pipeline and checks that a prototyped program call became a
 * CALLS edge.
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

/* ── Result helpers ────────────────────────────────────────────── */

static CBMFileResult *extract_rpg(const char *src, const char *path) {
    return cbm_extract_file(src, (int)strlen(src), CBM_LANG_RPG, "t", path, 0, NULL, NULL);
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

static int has_def_named(const CBMFileResult *r, const char *name) {
    for (int i = 0; i < r->defs.count; i++) {
        if (strcmp(r->defs.items[i].name, name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int count_label(const CBMFileResult *r, const char *label) {
    int n = 0;
    for (int i = 0; i < r->defs.count; i++) {
        if (strcmp(r->defs.items[i].label, label) == 0) {
            n++;
        }
    }
    return n;
}

/* A call with exactly this callee, from exactly this enclosing QN, on this
 * line (0 = any line). */
static int has_call(const CBMFileResult *r, const char *callee, const char *enclosing, int line) {
    for (int i = 0; i < r->calls.count; i++) {
        const CBMCall *c = &r->calls.items[i];
        if (strcmp(c->callee_name, callee) == 0 && strcmp(c->enclosing_func_qn, enclosing) == 0 &&
            (line == 0 || c->start_line == line)) {
            return 1;
        }
    }
    return 0;
}

static int has_callee(const CBMFileResult *r, const char *callee) {
    for (int i = 0; i < r->calls.count; i++) {
        if (strcmp(r->calls.items[i].callee_name, callee) == 0) {
            return 1;
        }
    }
    return 0;
}

static int has_import(const CBMFileResult *r, const char *local, const char *path) {
    for (int i = 0; i < r->imports.count; i++) {
        const CBMImport *imp = &r->imports.items[i];
        if (strcmp(imp->local_name, local) == 0 && strcmp(imp->module_path, path) == 0) {
            return 1;
        }
    }
    return 0;
}

static int str_eq(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

/* ── Fixed-form source builder ─────────────────────────────────── */

typedef struct {
    char buf[8192];
    size_t len;
} Src;

static void put(Src *s, const char *line) {
    int n = snprintf(s->buf + s->len, sizeof(s->buf) - s->len, "%s\n", line);
    if (n > 0) {
        s->len += (size_t)n;
    }
}

/* RPG IV D-spec: name 7-21, definition type 24-25, from 26-32, to/length
 * 33-39, data type 40, decimals 41-42, keywords from 44. */
static void d_spec(Src *s, const char *name, const char *deftype, const char *from, const char *len,
                   const char *type, const char *dec, const char *keywords) {
    char line[160];
    snprintf(line, sizeof(line), "     D%-15s  %-2s%7s%7s%1s%-2s %s", name, deftype, from, len,
             type, dec, keywords);
    put(s, line);
}

/* RPG IV C-spec: factor 1 12-25, opcode 26-35, factor 2 36-49, result 50-63. */
static void c_spec(Src *s, const char *f1, const char *op, const char *f2, const char *result) {
    char line[160];
    snprintf(line, sizeof(line), "     C     %-14s%-10s%-14s%-14s", f1, op, f2, result);
    put(s, line);
}

/* RPG IV C-spec with an extended factor 2 (columns 36-80). A blank opcode is a
 * continuation of the previous line's expression. */
static void c_expr(Src *s, const char *op, const char *expr) {
    char line[160];
    snprintf(line, sizeof(line), "     C     %-14s%-10s%s", "", op, expr);
    put(s, line);
}

/* RPG IV P-spec: name 7-21, B/E in 24, keywords from 44. */
static void p_spec(Src *s, const char *name, const char *kind, const char *keywords) {
    char line[160];
    snprintf(line, sizeof(line), "     P%-15s  %1s                   %s", name, kind, keywords);
    put(s, line);
}

/* RPG II/III C-spec: factor 1 18-27, opcode 28-32, factor 2 33-42, result 43-48. */
static void c3_spec(Src *s, const char *f1, const char *op, const char *f2, const char *result) {
    char line[160];
    snprintf(line, sizeof(line), "     C           %-10s%-5s%-10s%-6s", f1, op, f2, result);
    put(s, line);
}

static void comment(Src *s, const char *text) {
    char line[160];
    snprintf(line, sizeof(line), "      * %s", text);
    put(s, line);
}

/* A free-form statement inside fixed-form source: columns 8-80. */
static void free_line(Src *s, const char *text) {
    char line[160];
    snprintf(line, sizeof(line), "       %s", text);
    put(s, line);
}

/* ── Free-form fixture ─────────────────────────────────────────── */

/* qrpglesrc/custmnt.sqlrpgle: module t.qrpglesrc.custmnt, program CUSTMNT. */
static const char FREE_PROGRAM[] = "**FREE\n"                                     /* 1 */
                                   "ctl-opt dftactgrp(*no) actgrp(*new);\n"       /* 2 */
                                   "/copy qrpglesrc,custpr\n"                     /* 3 */
                                   "/include 'qcpysrc/errors.rpgleinc'\n"         /* 4 */
                                   "dcl-f custmast usage(*input) keyed;\n"        /* 5 */
                                   "\n"                                           /* 6 */
                                   "// Customer record layout\n"                  /* 7 */
                                   "dcl-ds customer qualified template;\n"        /* 8 */
                                   "  id packed(7:0);\n"                          /* 9 */
                                   "  name char(30);\n"                           /* 10 */
                                   "  balance packed(15:2);\n"                    /* 11 */
                                   "end-ds;\n"                                    /* 12 */
                                   "dcl-ds *n;\n"                                 /* 13 */
                                   "  workArea char(100);\n"                      /* 14 */
                                   "end-ds;\n"                                    /* 15 */
                                   "dcl-enum status qualified;\n"                 /* 16 */
                                   "  active 1;\n"                                /* 17 */
                                   "  closed 2;\n"                                /* 18 */
                                   "end-enum;\n"                                  /* 19 */
                                   "dcl-s counter int(10) inz(0);\n"              /* 20 */
                                   "dcl-s names char(30) dim(50);\n"              /* 21 */
                                   "dcl-c MAX_ROWS 100;\n"                        /* 22 */
                                   "dcl-pr getCustomer extpgm('GETCUST');\n"      /* 23 */
                                   "  id packed(7:0) const;\n"                    /* 24 */
                                   "end-pr;\n"                                    /* 25 */
                                   "dcl-pr logMessage extproc('log_message');\n"  /* 26 */
                                   "  msg varchar(200) const;\n"                  /* 27 */
                                   "end-pr;\n"                                    /* 28 */
                                   "dcl-pr formatName;\n"                         /* 29 */
                                   "  name char(30) const;\n"                     /* 30 */
                                   "end-pr;\n"                                    /* 31 */
                                   "dcl-pr FILEUTIL extpgm end-pr;\n"             /* 32 */
                                   "dcl-pi *n;\n"                                 /* 33 */
                                   "  custId packed(7:0) const;\n"                /* 34 */
                                   "end-pi;\n"                                    /* 35 */
                                   "\n"                                           /* 36 */
                                   "exsr init;\n"                                 /* 37 */
                                   "getCustomer(custId);\n"                       /* 38 */
                                   "logMessage('start; // not a comment');\n"     /* 39 */
                                   "callp(e) FILEUTIL();\n"                       /* 40 */
                                   "counter = %len(names(1))\n"                   /* 41 */
                                   "          + calcTotal(custId : 2);\n"         /* 42 */
                                   "exec sql call proc_audit(:custId);\n"         /* 43 */
                                   "if counter > MAX_ROWS and custId <> 0;\n"     /* 44 */
                                   "  dow not %eof(custmast);\n"                  /* 45 */
                                   "    read custmast;\n"                         /* 46 */
                                   "  enddo;\n"                                   /* 47 */
                                   "endif;\n"                                     /* 48 */
                                   "*inlr = *on;\n"                               /* 49 */
                                   "return;\n"                                    /* 50 */
                                   "\n"                                           /* 51 */
                                   "begsr init;\n"                                /* 52 */
                                   "  counter = 0;\n"                             /* 53 */
                                   "endsr;\n"                                     /* 54 */
                                   "\n"                                           /* 55 */
                                   "// Adds up the order total for a customer.\n" /* 56 */
                                   "DCL-PROC calcTotal EXPORT;\n"                 /* 57 */
                                   "  dcl-pi *n packed(15:2);\n"                  /* 58 */
                                   "    id packed(7:0) const;\n"                  /* 59 */
                                   "    factor int(10) value;\n"                  /* 60 */
                                   "  end-pi;\n"                                  /* 61 */
                                   "  dcl-s total packed(15:2);\n"                /* 62 */
                                   "  dcl-ds localDs qualified;\n"                /* 63 */
                                   "    x int(10);\n"                             /* 64 */
                                   "  end-ds;\n"                                  /* 65 */
                                   "  exsr accumulate;\n"                         /* 66 */
                                   "  formatName('x');\n"                         /* 67 */
                                   "  return total * factor;\n"                   /* 68 */
                                   "  begsr accumulate;\n"                        /* 69 */
                                   "    total += id;\n"                           /* 70 */
                                   "  endsr;\n"                                   /* 71 */
                                   "end-proc;\n";                                 /* 72 */

static const char FREE_PATH[] = "qrpglesrc/custmnt.sqlrpgle";
static const char FREE_MODULE[] = "t.qrpglesrc.custmnt";
static const char FREE_PROGRAM_QN[] = "t.qrpglesrc.custmnt.CUSTMNT";
static const char FREE_PROC_QN[] = "t.qrpglesrc.custmnt.calcTotal";

TEST(rpg_free_module_program_and_procedures) {
    CBMFileResult *r = extract_rpg(FREE_PROGRAM, FREE_PATH);
    ASSERT_NOT_NULL(r);
    ASSERT_FALSE(r->has_error);
    ASSERT_NULL(r->cached_tree);

    const CBMDefinition *mod = &r->defs.items[0];
    ASSERT_STR_EQ(mod->label, "Module");
    ASSERT_STR_EQ(mod->qualified_name, FREE_MODULE);
    ASSERT_EQ(mod->start_line, 1);
    ASSERT_EQ(mod->end_line, 72);

    /* The program spans its main line, from the first executable statement to
     * the last one, and is the entry point. */
    const CBMDefinition *pgm = find_def(r, "Function", "CUSTMNT");
    ASSERT_NOT_NULL(pgm);
    ASSERT_STR_EQ(pgm->qualified_name, FREE_PROGRAM_QN);
    ASSERT_EQ(pgm->start_line, 37);
    ASSERT_EQ(pgm->end_line, 54);
    ASSERT_TRUE(pgm->is_entry_point);
    ASSERT_STR_EQ(pgm->signature, "(custId packed(7:0))");

    const CBMDefinition *proc = find_def(r, "Function", "calcTotal");
    ASSERT_NOT_NULL(proc);
    ASSERT_STR_EQ(proc->qualified_name, FREE_PROC_QN);
    ASSERT_EQ(proc->start_line, 57);
    ASSERT_EQ(proc->end_line, 72);
    ASSERT_TRUE(proc->is_exported);
    ASSERT_FALSE(proc->is_entry_point);
    ASSERT_STR_EQ(proc->return_type, "packed(15:2)");
    ASSERT_STR_EQ(proc->signature, "(id packed(7:0), factor int(10))");
    ASSERT_EQ(proc->param_count, 2);
    ASSERT_STR_EQ(proc->param_names[1], "factor");
    ASSERT_STR_EQ(proc->param_types[1], "int(10)");
    ASSERT_STR_EQ(proc->docstring, "Adds up the order total for a customer.");

    /* Subroutines nest under their owner. */
    const CBMDefinition *init = find_def(r, "Function", "init");
    ASSERT_NOT_NULL(init);
    ASSERT_STR_EQ(init->qualified_name, "t.qrpglesrc.custmnt.CUSTMNT.init");
    ASSERT_EQ(init->start_line, 52);
    ASSERT_EQ(init->end_line, 54);
    const CBMDefinition *acc = find_def(r, "Function", "accumulate");
    ASSERT_NOT_NULL(acc);
    ASSERT_STR_EQ(acc->qualified_name, "t.qrpglesrc.custmnt.calcTotal.accumulate");
    ASSERT_EQ(acc->start_line, 69);
    ASSERT_EQ(acc->end_line, 71);
    ASSERT_EQ(count_label(r, "Function"), 4);
    cbm_free_result(r);
    PASS();
}

TEST(rpg_free_data_definitions) {
    CBMFileResult *r = extract_rpg(FREE_PROGRAM, FREE_PATH);
    ASSERT_NOT_NULL(r);

    const CBMDefinition *ds = find_def(r, "Struct", "customer");
    ASSERT_NOT_NULL(ds);
    ASSERT_STR_EQ(ds->qualified_name, "t.qrpglesrc.custmnt.customer");
    ASSERT_EQ(ds->start_line, 8);
    ASSERT_EQ(ds->end_line, 12);
    ASSERT_STR_EQ(ds->docstring, "Customer record layout");
    const CBMDefinition *balance = find_def(r, "Field", "balance");
    ASSERT_NOT_NULL(balance);
    ASSERT_STR_EQ(balance->qualified_name, "t.qrpglesrc.custmnt.customer.balance");
    ASSERT_STR_EQ(balance->parent_class, "t.qrpglesrc.custmnt.customer");
    ASSERT_STR_EQ(balance->return_type, "packed(15:2)");
    ASSERT_EQ(balance->start_line, 11);

    /* An unnamed data structure's subfields are module-level variables. */
    ASSERT_NOT_NULL(find_def(r, "Variable", "workArea"));
    ASSERT_STR_EQ(find_def(r, "Variable", "workArea")->qualified_name,
                  "t.qrpglesrc.custmnt.workArea");

    const CBMDefinition *en = find_def(r, "Enum", "status");
    ASSERT_NOT_NULL(en);
    ASSERT_EQ(en->start_line, 16);
    ASSERT_EQ(en->end_line, 19);
    ASSERT_STR_EQ(find_def(r, "Field", "closed")->parent_class, "t.qrpglesrc.custmnt.status");

    const CBMDefinition *names = find_def(r, "Variable", "names");
    ASSERT_NOT_NULL(names);
    ASSERT_STR_EQ(names->return_type, "char(30)");
    ASSERT_NOT_NULL(find_def(r, "Variable", "counter"));
    ASSERT_NOT_NULL(find_def(r, "Variable", "MAX_ROWS"));

    /* Locals of a procedure are not module-level definitions, and a
     * prototype is a binding, not a definition. */
    ASSERT_FALSE(has_def_named(r, "total"));
    ASSERT_FALSE(has_def_named(r, "localDs"));
    ASSERT_FALSE(has_def_named(r, "x"));
    ASSERT_FALSE(has_def_named(r, "getCustomer"));
    ASSERT_FALSE(has_def_named(r, "custmast"));
    ASSERT_EQ(count_label(r, "Struct"), 1);
    ASSERT_EQ(count_label(r, "Variable"), 4);
    cbm_free_result(r);
    PASS();
}

TEST(rpg_free_calls) {
    CBMFileResult *r = extract_rpg(FREE_PROGRAM, FREE_PATH);
    ASSERT_NOT_NULL(r);

    /* exsr: the subroutine's QN tail, so same-module lookup is exact. */
    ASSERT_TRUE(has_call(r, "CUSTMNT.init", FREE_PROGRAM_QN, 37));
    ASSERT_TRUE(has_call(r, "calcTotal.accumulate", FREE_PROC_QN, 66));
    /* Prototyped calls resolve to the external program or procedure. */
    ASSERT_TRUE(has_call(r, "GETCUST", FREE_PROGRAM_QN, 38));
    ASSERT_TRUE(has_call(r, "log_message", FREE_PROGRAM_QN, 39));
    ASSERT_TRUE(has_call(r, "FILEUTIL", FREE_PROGRAM_QN, 40));
    ASSERT_TRUE(has_call(r, "formatName", FREE_PROC_QN, 67));
    /* A call inside an expression, on the line the statement started. */
    ASSERT_TRUE(has_call(r, "calcTotal", FREE_PROGRAM_QN, 41));
    /* exec sql call names an IBM i object. */
    ASSERT_TRUE(has_call(r, "PROC_AUDIT", FREE_PROGRAM_QN, 43));

    /* Array subscripts, built-in functions and opcodes are not calls. */
    ASSERT_FALSE(has_callee(r, "names"));
    ASSERT_FALSE(has_callee(r, "len"));
    ASSERT_FALSE(has_callee(r, "eof"));
    ASSERT_FALSE(has_callee(r, "if"));
    ASSERT_FALSE(has_callee(r, "dow"));
    ASSERT_EQ(r->calls.count, 8);
    cbm_free_result(r);
    PASS();
}

TEST(rpg_free_imports_and_metrics) {
    CBMFileResult *r = extract_rpg(FREE_PROGRAM, FREE_PATH);
    ASSERT_NOT_NULL(r);
    ASSERT_EQ(r->imports.count, 2);
    ASSERT_TRUE(has_import(r, "custpr", "qrpglesrc/custpr"));
    ASSERT_TRUE(has_import(r, "errors", "qcpysrc/errors.rpgleinc"));

    /* Main line: if, and, dow. */
    const CBMDefinition *pgm = find_def(r, "Function", "CUSTMNT");
    ASSERT_NOT_NULL(pgm);
    ASSERT_EQ(pgm->complexity, 4);
    ASSERT_EQ(pgm->loop_count, 1);
    ASSERT_EQ(pgm->loop_depth, 1);
    ASSERT_EQ(pgm->lines, 18);
    const CBMDefinition *proc = find_def(r, "Function", "calcTotal");
    ASSERT_NOT_NULL(proc);
    ASSERT_EQ(proc->complexity, 1);
    ASSERT_EQ(proc->loop_count, 0);
    cbm_free_result(r);
    PASS();
}

/* ── Fixed-form RPG IV ─────────────────────────────────────────── */

/* QRPGLESRC/CUSTRPT.RPGLE: module t.QRPGLESRC.CUSTRPT, program CUSTRPT. */
static void build_fixed_iv(Src *s) {
    put(s, "     H DFTACTGRP(*NO) ACTGRP(*NEW)");                    /* 1 */
    put(s, "     FCUSTMAST  IF   E           K DISK");               /* 2 */
    comment(s, "Prototype for the customer program");                /* 3 */
    d_spec(s, "GETCUST", "PR", "", "", "", "", "EXTPGM('GETCUST')"); /* 4 */
    d_spec(s, " CUSTID", "", "", "7", "P", "0", "CONST");            /* 5 */
    d_spec(s, "LOGMSG", "PR", "", "", "", "", "");                   /* 6 */
    d_spec(s, "", "", "", "", "", "", "EXTPROC('log_message')");     /* 7 */
    d_spec(s, " MSG", "", "", "200", "A", "", "CONST VARYING");      /* 8 */
    comment(s, "Customer record");                                   /* 9 */
    d_spec(s, "CUSTDS", "DS", "", "", "", "", "QUALIFIED");          /* 10 */
    d_spec(s, " ID", "", "", "7", "P", "0", "");                     /* 11 */
    d_spec(s, " NAME", "", "", "30", "A", "", "");                   /* 12 */
    d_spec(s, " BALANCE", "", "", "15", "P", "2", "");               /* 13 */
    d_spec(s, "COUNTER", "S", "", "10", "I", "0", "INZ(0)");         /* 14 */
    d_spec(s, "NAMES", "S", "", "30", "A", "", "DIM(50)");           /* 15 */
    d_spec(s, "MAXROWS", "C", "", "", "", "", "CONST(100)");         /* 16 */
    d_spec(s, "", "PI", "", "", "", "", "");                         /* 17 */
    d_spec(s, " CUSTID", "", "", "7", "P", "0", "CONST");            /* 18 */
    c_spec(s, "", "EXSR", "INIT", "");                               /* 19 */
    c_expr(s, "CALLP", "GETCUST(CUSTID)");                           /* 20 */
    c_spec(s, "", "CALL", "'ORDPGM'", "");                           /* 21 */
    c_spec(s, "", "CALLB", "'do_work'", "");                         /* 22 */
    c_expr(s, "EVAL", "COUNTER = %LEN(NAMES(1)) +");                 /* 23 */
    c_expr(s, "", "CALCTOT(CUSTID : 2)");                            /* 24 */
    c_spec(s, "CUSTID", "CASEQ", "0", "INIT");                       /* 25 */
    c_spec(s, "", "ENDCS", "", "");                                  /* 26 */
    c_expr(s, "IF", "COUNTER > MAXROWS AND CUSTID <> 0");            /* 27 */
    c_expr(s, "DOW", "NOT %EOF(CUSTMAST)");                          /* 28 */
    c_spec(s, "", "READ", "CUSTMAST", "");                           /* 29 */
    c_spec(s, "", "ENDDO", "", "");                                  /* 30 */
    c_spec(s, "", "ENDIF", "", "");                                  /* 31 */
    c_expr(s, "EVAL", "*INLR = *ON");                                /* 32 */
    c_spec(s, "", "RETURN", "", "");                                 /* 33 */
    c_spec(s, "INIT", "BEGSR", "", "");                              /* 34 */
    c_expr(s, "EVAL", "COUNTER = 0");                                /* 35 */
    c_spec(s, "", "ENDSR", "", "");                                  /* 36 */
    comment(s, "Adds up the order total");                           /* 37 */
    p_spec(s, "CALCTOT", "B", "EXPORT");                             /* 38 */
    d_spec(s, "CALCTOT", "PI", "", "15", "P", "2", "");              /* 39 */
    d_spec(s, " ID", "", "", "7", "P", "0", "CONST");                /* 40 */
    d_spec(s, " FACTOR", "", "", "10", "I", "0", "VALUE");           /* 41 */
    d_spec(s, "TOTAL", "S", "", "15", "P", "2", "");                 /* 42 */
    c_spec(s, "", "EXSR", "ACCUM", "");                              /* 43 */
    c_expr(s, "RETURN", "TOTAL * FACTOR");                           /* 44 */
    c_spec(s, "ACCUM", "BEGSR", "", "");                             /* 45 */
    c_expr(s, "EVAL", "TOTAL = TOTAL + ID");                         /* 46 */
    c_spec(s, "", "ENDSR", "", "");                                  /* 47 */
    p_spec(s, "CALCTOT", "E", "");                                   /* 48 */
    comment(s, "nomain in a comment is not a control option");       /* 49 */
    put(s, "**CTDATA NAMES");                                        /* 50 */
    put(s, "C EXSR NOTCODE(1)");                                     /* 51 */
}

static const char FIXED_PATH[] = "QRPGLESRC/CUSTRPT.RPGLE";
static const char FIXED_PROGRAM_QN[] = "t.QRPGLESRC.CUSTRPT.CUSTRPT";
static const char FIXED_PROC_QN[] = "t.QRPGLESRC.CUSTRPT.CALCTOT";

TEST(rpg_fixed_iv_definitions) {
    Src s = {{0}, 0};
    build_fixed_iv(&s);
    CBMFileResult *r = extract_rpg(s.buf, FIXED_PATH);
    ASSERT_NOT_NULL(r);
    ASSERT_FALSE(r->has_error);
    ASSERT_STR_EQ(r->defs.items[0].qualified_name, "t.QRPGLESRC.CUSTRPT");

    const CBMDefinition *pgm = find_def(r, "Function", "CUSTRPT");
    ASSERT_NOT_NULL(pgm);
    ASSERT_STR_EQ(pgm->qualified_name, FIXED_PROGRAM_QN);
    ASSERT_EQ(pgm->start_line, 19);
    ASSERT_EQ(pgm->end_line, 36);
    ASSERT_TRUE(pgm->is_entry_point);
    ASSERT_STR_EQ(pgm->signature, "(CUSTID packed(7:0))");

    const CBMDefinition *proc = find_def(r, "Function", "CALCTOT");
    ASSERT_NOT_NULL(proc);
    ASSERT_STR_EQ(proc->qualified_name, FIXED_PROC_QN);
    ASSERT_EQ(proc->start_line, 38);
    ASSERT_EQ(proc->end_line, 48);
    ASSERT_TRUE(proc->is_exported);
    ASSERT_STR_EQ(proc->return_type, "packed(15:2)");
    ASSERT_STR_EQ(proc->signature, "(ID packed(7:0), FACTOR int(10))");
    ASSERT_STR_EQ(proc->docstring, "Adds up the order total");

    ASSERT_STR_EQ(find_def(r, "Function", "INIT")->qualified_name,
                  "t.QRPGLESRC.CUSTRPT.CUSTRPT.INIT");
    const CBMDefinition *accum = find_def(r, "Function", "ACCUM");
    ASSERT_NOT_NULL(accum);
    ASSERT_STR_EQ(accum->qualified_name, "t.QRPGLESRC.CUSTRPT.CALCTOT.ACCUM");
    ASSERT_EQ(accum->start_line, 45);
    ASSERT_EQ(accum->end_line, 47);

    const CBMDefinition *ds = find_def(r, "Struct", "CUSTDS");
    ASSERT_NOT_NULL(ds);
    ASSERT_EQ(ds->start_line, 10);
    ASSERT_EQ(ds->end_line, 13);
    ASSERT_STR_EQ(ds->docstring, "Customer record");
    ASSERT_STR_EQ(find_def(r, "Field", "NAME")->return_type, "char(30)");
    ASSERT_STR_EQ(find_def(r, "Field", "BALANCE")->return_type, "packed(15:2)");
    ASSERT_STR_EQ(find_def(r, "Field", "BALANCE")->parent_class, "t.QRPGLESRC.CUSTRPT.CUSTDS");
    ASSERT_STR_EQ(find_def(r, "Variable", "COUNTER")->return_type, "int(10)");
    ASSERT_NOT_NULL(find_def(r, "Variable", "NAMES"));
    ASSERT_NOT_NULL(find_def(r, "Variable", "MAXROWS"));
    ASSERT_FALSE(has_def_named(r, "TOTAL"));
    ASSERT_FALSE(has_def_named(r, "GETCUST"));
    ASSERT_FALSE(has_def_named(r, "LOGMSG"));

    /* Compile-time data after ** is not source. */
    ASSERT_FALSE(has_callee(r, "NOTCODE"));
    cbm_free_result(r);
    PASS();
}

TEST(rpg_fixed_iv_calls_and_metrics) {
    Src s = {{0}, 0};
    build_fixed_iv(&s);
    CBMFileResult *r = extract_rpg(s.buf, FIXED_PATH);
    ASSERT_NOT_NULL(r);

    ASSERT_TRUE(has_call(r, "CUSTRPT.INIT", FIXED_PROGRAM_QN, 19));
    ASSERT_TRUE(has_call(r, "GETCUST", FIXED_PROGRAM_QN, 20));
    ASSERT_TRUE(has_call(r, "ORDPGM", FIXED_PROGRAM_QN, 21));
    ASSERT_TRUE(has_call(r, "do_work", FIXED_PROGRAM_QN, 22));
    /* The call sits on the continuation line of an EVAL; the site is the
     * opcode line. */
    ASSERT_TRUE(has_call(r, "CALCTOT", FIXED_PROGRAM_QN, 23));
    /* CASxx calls the subroutine in its result field. */
    ASSERT_TRUE(has_call(r, "CUSTRPT.INIT", FIXED_PROGRAM_QN, 25));
    ASSERT_TRUE(has_call(r, "CALCTOT.ACCUM", FIXED_PROC_QN, 43));
    ASSERT_FALSE(has_callee(r, "NAMES"));
    ASSERT_FALSE(has_callee(r, "LEN"));
    ASSERT_FALSE(has_callee(r, "EOF"));
    ASSERT_EQ(r->calls.count, 7);

    /* Main line: CASEQ, IF, AND, DOW. */
    const CBMDefinition *pgm = find_def(r, "Function", "CUSTRPT");
    ASSERT_NOT_NULL(pgm);
    ASSERT_EQ(pgm->complexity, 5);
    ASSERT_EQ(pgm->loop_count, 1);
    ASSERT_EQ(pgm->loop_depth, 1);
    cbm_free_result(r);
    PASS();
}

/* Fixed-form declarations with a /FREE block and a column-7 /COPY. The
 * prototype is upper case, the call is not: RPG names are case-insensitive. */
TEST(rpg_mixed_fixed_and_free) {
    Src s = {{0}, 0};
    put(&s, "      /COPY QRPGLESRC,PROTOS");                          /* 1 */
    d_spec(&s, "GETCUST", "PR", "", "", "", "", "EXTPGM('GETCUST')"); /* 2 */
    d_spec(&s, " CUSTID", "", "", "7", "P", "0", "CONST");            /* 3 */
    put(&s, "      /FREE");                                           /* 4 */
    free_line(&s, "getCust(1);");                                     /* 5 */
    free_line(&s, "exsr done;");                                      /* 6 */
    free_line(&s, "*inlr = *on;");                                    /* 7 */
    free_line(&s, "begsr done;");                                     /* 8 */
    free_line(&s, "endsr;");                                          /* 9 */
    put(&s, "      /END-FREE");                                       /* 10 */
    CBMFileResult *r = extract_rpg(s.buf, "qrpglesrc/mixed.rpgle");
    ASSERT_NOT_NULL(r);
    ASSERT_TRUE(has_import(r, "PROTOS", "QRPGLESRC/PROTOS"));
    const CBMDefinition *pgm = find_def(r, "Function", "MIXED");
    ASSERT_NOT_NULL(pgm);
    ASSERT_EQ(pgm->start_line, 5);
    ASSERT_EQ(pgm->end_line, 9);
    ASSERT_TRUE(has_call(r, "GETCUST", "t.qrpglesrc.mixed.MIXED", 5));
    ASSERT_TRUE(has_call(r, "MIXED.done", "t.qrpglesrc.mixed.MIXED", 6));
    ASSERT_EQ(r->calls.count, 2);
    cbm_free_result(r);
    PASS();
}

/* ── RPG II/III ────────────────────────────────────────────────── */

TEST(rpg3_program) {
    Src s = {{0}, 0};
    put(&s, "     H");                       /* 1 */
    comment(&s, "Order entry");              /* 2 */
    put(&s, "      /COPY QRPGSRC,ORDCPY");   /* 3 */
    c3_spec(&s, "", "EXSR", "INIT", "");     /* 4 */
    c3_spec(&s, "", "CALL", "'ORDUPD'", ""); /* 5 */
    c3_spec(&s, "CUSTNO", "IFEQ", "0", "");  /* 6 */
    c3_spec(&s, "", "EXSR", "ERRSR", "");    /* 7 */
    c3_spec(&s, "", "END", "", "");          /* 8 */
    c3_spec(&s, "", "CALL", "PGMVAR", "");   /* 9 */
    c3_spec(&s, "INIT", "BEGSR", "", "");    /* 10 */
    c3_spec(&s, "", "ENDSR", "", "");        /* 11 */
    c3_spec(&s, "ERRSR", "BEGSR", "", "");   /* 12 */
    c3_spec(&s, "", "ENDSR", "", "");        /* 13 */
    CBMFileResult *r = extract_rpg(s.buf, "qrpgsrc/ordent.rpg");
    ASSERT_NOT_NULL(r);
    ASSERT_FALSE(r->has_error);
    const char *pgm_qn = "t.qrpgsrc.ordent.ORDENT";
    const CBMDefinition *pgm = find_def(r, "Function", "ORDENT");
    ASSERT_NOT_NULL(pgm);
    ASSERT_EQ(pgm->start_line, 4);
    ASSERT_EQ(pgm->end_line, 13);
    ASSERT_EQ(pgm->complexity, 2);
    ASSERT_NOT_NULL(find_def(r, "Function", "INIT"));
    ASSERT_NOT_NULL(find_def(r, "Function", "ERRSR"));
    ASSERT_TRUE(has_import(r, "ORDCPY", "QRPGSRC/ORDCPY"));
    ASSERT_TRUE(has_call(r, "ORDENT.INIT", pgm_qn, 4));
    ASSERT_TRUE(has_call(r, "ORDUPD", pgm_qn, 5));
    ASSERT_TRUE(has_call(r, "ORDENT.ERRSR", pgm_qn, 7));
    /* CALL through a variable has no static target. */
    ASSERT_FALSE(has_callee(r, "PGMVAR"));
    ASSERT_EQ(r->calls.count, 3);
    cbm_free_result(r);
    PASS();
}

/* ── Control options, copybooks, lexing ────────────────────────── */

TEST(rpg_nomain_module_has_no_program) {
    CBMFileResult *r = extract_rpg("**FREE\n"
                                   "ctl-opt nomain;\n"
                                   "dcl-proc util export;\n"
                                   "  dcl-pi *n int(10); end-pi;\n"
                                   "  return 1;\n"
                                   "end-proc;\n",
                                   "qrpglesrc/utils.rpgle");
    ASSERT_NOT_NULL(r);
    ASSERT_FALSE(has_def_named(r, "UTILS"));
    const CBMDefinition *util = find_def(r, "Function", "util");
    ASSERT_NOT_NULL(util);
    ASSERT_STR_EQ(util->return_type, "int(10)");
    ASSERT_EQ(count_label(r, "Function"), 1);
    cbm_free_result(r);
    PASS();
}

/* A linear-main program is entered through the named procedure; the program
 * def mirrors that procedure's range so CALL 'BATCH' still has a target. The
 * member name is the basename up to its first dot (ibmi-bob's name.pgm.rpgle). */
TEST(rpg_linear_main_program_mirrors_procedure) {
    CBMFileResult *r = extract_rpg("**FREE\n"
                                   "ctl-opt main(run);\n"
                                   "dcl-proc run;\n"
                                   "  return;\n"
                                   "end-proc;\n",
                                   "qrpglesrc/batch.pgm.rpgle");
    ASSERT_NOT_NULL(r);
    const CBMDefinition *pgm = find_def(r, "Function", "BATCH");
    ASSERT_NOT_NULL(pgm);
    ASSERT_TRUE(pgm->is_entry_point);
    ASSERT_EQ(pgm->start_line, 3);
    ASSERT_EQ(pgm->end_line, 5);
    ASSERT_NOT_NULL(find_def(r, "Function", "run"));
    ASSERT_EQ(count_label(r, "Function"), 2);
    cbm_free_result(r);
    PASS();
}

TEST(rpg_copybook_is_module_only) {
    CBMFileResult *r = extract_rpg("**FREE\n"
                                   "dcl-pr getCustomer extpgm('GETCUST');\n"
                                   "  id packed(7:0) const;\n"
                                   "end-pr;\n"
                                   "dcl-c ERR_NOTFOUND 'not found';\n",
                                   "qrpglesrc/custpr.rpgleinc");
    ASSERT_NOT_NULL(r);
    ASSERT_EQ(count_label(r, "Module"), 1);
    ASSERT_EQ(count_label(r, "Function"), 0);
    ASSERT_NOT_NULL(find_def(r, "Variable", "ERR_NOTFOUND"));
    ASSERT_EQ(r->calls.count, 0);
    cbm_free_result(r);
    PASS();
}

/* The three member forms of /copy plus the two IFS forms. A bare member
 * defaults to QRPGLESRC as the compiler does; text after the first blank is
 * a comment. */
TEST(rpg_copy_directive_forms) {
    CBMFileResult *r = extract_rpg("**FREE\n"
                                   "/copy custpr\n"
                                   "/COPY MYLIB/QPROTOSRC,PROTOS   shared prototypes\n"
                                   "/include qcpysrc/errors.rpgleinc\n"
                                   "/include \"inc/with blank.rpgleinc\"\n",
                                   "qrpglesrc/copies.rpgle");
    ASSERT_NOT_NULL(r);
    ASSERT_EQ(r->imports.count, 4);
    ASSERT_TRUE(has_import(r, "custpr", "QRPGLESRC/custpr"));
    ASSERT_TRUE(has_import(r, "PROTOS", "QPROTOSRC/PROTOS"));
    ASSERT_TRUE(has_import(r, "errors", "qcpysrc/errors.rpgleinc"));
    ASSERT_TRUE(has_import(r, "with blank", "inc/with blank.rpgleinc"));
    cbm_free_result(r);
    PASS();
}

/* Statement lexing: quotes doubled inside a literal, `;` and `//` inside a
 * literal, a `...` long-name continuation, a hyphenated opcode with an
 * extender, and a last statement with no `;`. */
TEST(rpg_free_statement_lexing) {
    CBMFileResult *r = extract_rpg("**FREE\n"
                                   "dcl-s message varchar(50) inz('it''s ; fine // really');\n"
                                   "dcl-proc aVeryLongProcedureName...\n"
                                   "  ThatContinues export;\n"
                                   "  message = 'x';\n"
                                   "  xml-into(e) message %xml('<a/>' : 'doc=string');\n"
                                   "end-proc;\n"
                                   "exsr fin;\n"
                                   "begsr fin;\n"
                                   "endsr",
                                   "qrpglesrc/lex.rpgle");
    ASSERT_NOT_NULL(r);
    ASSERT_NOT_NULL(find_def(r, "Variable", "message"));
    const CBMDefinition *proc = find_def(r, "Function", "aVeryLongProcedureNameThatContinues");
    ASSERT_NOT_NULL(proc);
    ASSERT_TRUE(proc->is_exported);
    ASSERT_EQ(proc->start_line, 3);
    ASSERT_EQ(proc->end_line, 7);
    const CBMDefinition *fin = find_def(r, "Function", "fin");
    ASSERT_NOT_NULL(fin);
    ASSERT_EQ(fin->end_line, 10);
    ASSERT_TRUE(has_call(r, "LEX.fin", "t.qrpglesrc.lex.LEX", 8));
    ASSERT_FALSE(has_callee(r, "into"));
    ASSERT_EQ(r->calls.count, 1);
    cbm_free_result(r);
    PASS();
}

/* Fixed-form lines shorter than the comment column, a bare /EOF with no
 * trailing newline, and a `...` fragment abandoned before a C-spec: nothing
 * is read past the line and the fragment does not leak into the next name. */
TEST(rpg_fixed_short_lines) {
    Src s = {{0}, 0};
    put(&s, "     H");
    put(&s, "     D LONGNAME...");
    c_spec(&s, "INIT", "BEGSR", "", "");
    c_spec(&s, "", "ENDSR", "", "");
    put(&s, "  x");
    s.len += (size_t)snprintf(s.buf + s.len, sizeof(s.buf) - s.len, "/EOF");
    CBMFileResult *r = extract_rpg(s.buf, "qrpglesrc/short.rpgle");
    ASSERT_NOT_NULL(r);
    ASSERT_FALSE(r->has_error);
    ASSERT_NOT_NULL(find_def(r, "Function", "INIT"));
    ASSERT_FALSE(has_def_named(r, "LONGNAMEINIT"));
    cbm_free_result(r);
    PASS();
}

/* ── Pipeline: CALLS and IMPORTS edges across members ───────────── */

typedef struct {
    const char *name;
    const char *content;
} RpgFile;

typedef struct {
    char tmpdir[256];
    char dbpath[512];
    char *project;
    cbm_mcp_server_t *srv;
    cbm_store_t *store;
} RpgProj;

/* Write `files` under a fresh temp directory, index it through the MCP
 * index_repository tool and open the store it produced (the shape the grammar
 * probe suites use). */
static bool rpg_index(RpgProj *p, const RpgFile *files, int nfiles) {
    memset(p, 0, sizeof(*p));
    snprintf(p->tmpdir, sizeof(p->tmpdir), "/tmp/cbm_rpg_XXXXXX");
    if (!cbm_mkdtemp(p->tmpdir)) {
        return false;
    }
    for (int i = 0; i < nfiles; i++) {
        char path[700];
        snprintf(path, sizeof(path), "%s/%s", p->tmpdir, files[i].name);
        char *slash = strrchr(path, '/');
        if (slash && slash > path + strlen(p->tmpdir)) {
            *slash = '\0';
            cbm_mkdir_p(path, 0755);
            *slash = '/';
        }
        if (th_write_file(path, files[i].content) != 0) {
            return false;
        }
    }
    p->project = cbm_project_name_from_path(p->tmpdir);
    if (!p->project) {
        return false;
    }
    const char *home = getenv("HOME");
    if (!home) {
        home = "/tmp";
    }
    char cache_dir[512];
    snprintf(cache_dir, sizeof(cache_dir), "%s/.cache/codebase-memory-mcp", home);
    cbm_mkdir(cache_dir);
    snprintf(p->dbpath, sizeof(p->dbpath), "%s/%s.db", cache_dir, p->project);
    unlink(p->dbpath);
    p->srv = cbm_mcp_server_new(NULL);
    if (!p->srv) {
        return false;
    }
    char args[700];
    snprintf(args, sizeof(args), "{\"repo_path\":\"%s\"}", p->tmpdir);
    char *resp = cbm_mcp_handle_tool(p->srv, "index_repository", args);
    free(resp);
    p->store = cbm_store_open_path(p->dbpath);
    return p->store != NULL;
}

static void rpg_cleanup(RpgProj *p) {
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

/* A CALLS edge whose source QN ends with src_suffix and target QN ends with
 * tgt_suffix. */
static int rpg_calls_edge(cbm_store_t *store, const char *project, const char *src_suffix,
                          const char *tgt_suffix) {
    cbm_edge_t *edges = NULL;
    int n = 0;
    if (cbm_store_find_edges_by_type(store, project, "CALLS", &edges, &n) != CBM_STORE_OK) {
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
            found = sql >= ssl && str_eq(sq + sql - ssl, src_suffix) && tql >= tsl &&
                    str_eq(tq + tql - tsl, tgt_suffix);
        }
        cbm_node_free_fields(&src);
        cbm_node_free_fields(&tgt);
    }
    cbm_store_free_edges(edges, n);
    return found;
}

/* Two programs and a copybook: the prototyped call becomes a CALLS edge to
 * the callee program's Function node, and the /COPY becomes an IMPORTS edge to
 * the copybook's Module node. */
TEST(rpg_pipeline_resolves_program_call_and_copy) {
    static const RpgFile files[] = {
        {"QRPGLESRC/GETCUST.RPGLE", "**FREE\n"
                                    "ctl-opt dftactgrp(*no);\n"
                                    "dcl-pi *n;\n"
                                    "  id packed(7:0) const;\n"
                                    "end-pi;\n"
                                    "*inlr = *on;\n"
                                    "return;\n"},
        {"QRPGLESRC/CUSTPR.RPGLEINC", "**FREE\n"
                                      "dcl-pr formatAmount varchar(20);\n"
                                      "  amount packed(11:2) value;\n"
                                      "end-pr;\n"},
        {"QRPGLESRC/CUSTMNT.RPGLE", "**FREE\n"
                                    "/COPY QRPGLESRC,CUSTPR\n"
                                    "dcl-pr getCustomer extpgm('GETCUST');\n"
                                    "  id packed(7:0) const;\n"
                                    "end-pr;\n"
                                    "getCustomer(1);\n"
                                    "*inlr = *on;\n"},
    };
    RpgProj p;
    bool ok = rpg_index(&p, files, 3);
    int functions = 0;
    int calls = 0;
    int imports = 0;
    if (ok) {
        cbm_node_t *nodes = NULL;
        if (cbm_store_find_nodes_by_label(p.store, p.project, "Function", &nodes, &functions) ==
            CBM_STORE_OK) {
            cbm_store_free_nodes(nodes, functions);
        }
        calls = rpg_calls_edge(p.store, p.project, "CUSTMNT.CUSTMNT", "GETCUST.GETCUST");
        imports = cbm_store_count_edges_by_type(p.store, p.project, "IMPORTS");
    }
    rpg_cleanup(&p);
    ASSERT_TRUE(ok);
    ASSERT_EQ(functions, 2);
    ASSERT_TRUE(calls);
    ASSERT_EQ(imports, 1);
    PASS();
}

/* ── Suite ─────────────────────────────────────────────────────── */

SUITE(extraction_rpg) {
    RUN_TEST(rpg_free_module_program_and_procedures);
    RUN_TEST(rpg_free_data_definitions);
    RUN_TEST(rpg_free_calls);
    RUN_TEST(rpg_free_imports_and_metrics);
    RUN_TEST(rpg_fixed_iv_definitions);
    RUN_TEST(rpg_fixed_iv_calls_and_metrics);
    RUN_TEST(rpg_mixed_fixed_and_free);
    RUN_TEST(rpg3_program);
    RUN_TEST(rpg_nomain_module_has_no_program);
    RUN_TEST(rpg_linear_main_program_mirrors_procedure);
    RUN_TEST(rpg_copybook_is_module_only);
    RUN_TEST(rpg_copy_directive_forms);
    RUN_TEST(rpg_free_statement_lexing);
    RUN_TEST(rpg_fixed_short_lines);
    RUN_TEST(rpg_pipeline_resolves_program_call_and_copy);
}
