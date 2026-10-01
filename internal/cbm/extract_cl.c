// extract_cl.c — IBM i CL line scanner: CLP, CLLE and MNUCMD source members.
//
// CL members are registered under CBM_LANG_RPG (see extract_rpg.c) so that a
// CALL from CL to an RPG program and a DCLF of a DDS file resolve as
// same-language edges. The scanner emits:
//
//   Module    one per file
//   Function  the program, named after the source member, an entry point
//   calls     CALL PGM(X) / CALL X, SBMJOB CMD(CALL PGM(X) ...), emitted as
//             X.X (the program def's QN tail) like extract_rpg.c does;
//             CALLPRC PRC(p) as a bare procedure name
//   reads     DCLF, OVRDBF TOFILE, CPYF FROMFILE, OPNQRYF, RUNQRY QRYFILE,
//             CPYTOIMPF FROMFILE
//   writes    CPYF TOFILE, CLRPFM, RGZPFM, ADDPFM, CPYFRMIMPF TOFILE
//
// A statement ends at a line that does not end with `+` or `-` (a `+` also
// drops the leading blanks of the next line); `/* ... */` comments may span
// lines; a label is `NAME:` at the start of a statement. A file or program
// named through a variable (&X) or a special value (*LIBL, *ALL) has no static
// target and is skipped. The comment block before the first statement is the
// program's docstring.

#include "cbm.h"
#include "arena.h"
#include "foundation/constants.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum {
    CL_DOC_MAX = 1024,
    CL_STMT_INITIAL = 512,
    CL_NAME_MAX = 10,
};

typedef struct {
    CBMArena *a;
    CBMFileResult *result;
    const char *rel_path;
    const char *module_qn;
    const char *program_qn;

    char *stmt;
    int stmt_len;
    int stmt_cap;
    uint32_t stmt_line;
    bool skip_blanks; /* a `+` continuation drops the next line's leading blanks */
    bool in_comment;

    char doc[CL_DOC_MAX];
    int doc_len;
    bool doc_closed; /* the first statement was seen: later comments are not the docstring */
} ClState;

/* ── helpers ──────────────────────────────────────────────────────── */

static const char *cl_basename(const char *path) {
    const char *base = path;
    for (const char *p = path; p && *p; p++) {
        if (*p == '/' || *p == '\\') {
            base = p + 1;
        }
    }
    return base;
}

static bool cl_ieq(const char *a, const char *b) {
    if (!a || !b) {
        return false;
    }
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

bool cbm_ibmi_is_cl(const char *basename) {
    const char *dot = basename ? strrchr(basename, '.') : NULL;
    return dot && (cl_ieq(dot, ".clp") || cl_ieq(dot, ".clle") || cl_ieq(dot, ".clp38") ||
                   cl_ieq(dot, ".mnucmd"));
}

static bool cl_name_char(char c) {
    return isalnum((unsigned char)c) || c == '_' || c == '@' || c == '#' || c == '$';
}

/* Upper-cased copy of the object name at `p`: skips a `LIB/` or `*LIBL/`
 * qualifier and stops at the first blank or `)`. NULL for a variable (&X), a
 * special value (*X) or an empty/over-long token. */
static const char *cl_object_name(CBMArena *a, const char *p) {
    while (*p == '(' || isspace((unsigned char)*p)) {
        p++;
    }
    const char *start = p;
    while (*p && !isspace((unsigned char)*p) && *p != ')' && *p != '(') {
        p++;
    }
    const char *slash = NULL;
    for (const char *q = start; q < p; q++) {
        if (*q == '/') {
            slash = q;
        }
    }
    const char *name = slash ? slash + 1 : start;
    size_t n = (size_t)(p - name);
    if (n == 0 || n > CL_NAME_MAX || name[0] == '&' || name[0] == '*') {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        if (!cl_name_char(name[i])) {
            return NULL;
        }
    }
    char *out = cbm_arena_strndup(a, name, n);
    for (char *c = out; c && *c; c++) {
        *c = (char)toupper((unsigned char)*c);
    }
    return out;
}

/* Pointer just past `KEYWORD(` for the first occurrence of the keyword that
 * starts a token (preceded by a blank, `(` or the start), or NULL. */
static const char *cl_keyword(const char *stmt, const char *kw) {
    size_t klen = strlen(kw);
    for (const char *p = stmt; (p = strstr(p, kw)) != NULL; p += klen) {
        if ((p == stmt || isspace((unsigned char)p[-1]) || p[-1] == '(') && p[klen] == '(') {
            return p + klen + 1;
        }
    }
    return NULL;
}

/* ── graph emission ───────────────────────────────────────────────── */

static void cl_call(ClState *s, const char *target, bool is_program, uint32_t line) {
    if (!target) {
        return;
    }
    CBMCall call;
    memset(&call, 0, sizeof(call));
    call.callee_name = is_program ? cbm_arena_sprintf(s->a, "%s.%s", target, target) : target;
    call.enclosing_func_qn = s->program_qn;
    call.start_line = (int)line;
    cbm_calls_push(&s->result->calls, s->a, call);
}

static void cl_file(ClState *s, const char *name, bool is_write) {
    if (!name) {
        return;
    }
    CBMReadWrite rw = {.var_name = name, .enclosing_func_qn = s->program_qn, .is_write = is_write};
    cbm_rw_push(&s->result->rw, s->a, rw);
}

/* One complete statement (comments removed, continuations joined). */
static void cl_statement(ClState *s, const char *text, uint32_t line) {
    /* Drop a label: NAME: at the start. */
    const char *p = text;
    while (isspace((unsigned char)*p)) {
        p++;
    }
    const char *q = p;
    while (cl_name_char(*q)) {
        q++;
    }
    if (q > p && *q == ':') {
        p = q + 1;
        while (isspace((unsigned char)*p)) {
            p++;
        }
    }
    char *up = cbm_arena_strdup(s->a, p);
    if (!up) {
        return;
    }
    for (char *c = up; *c; c++) {
        *c = (char)toupper((unsigned char)*c);
    }
    const char *cmd_end = up;
    while (cl_name_char(*cmd_end)) {
        cmd_end++;
    }
    size_t cmd_len = (size_t)(cmd_end - up);
    if (cmd_len == 0) {
        return;
    }
#define CMD_IS(lit) (cmd_len == sizeof(lit) - 1 && strncmp(up, lit, cmd_len) == 0)
    if (CMD_IS("CALL")) {
        const char *pgm = cl_keyword(up, "PGM");
        cl_call(s, cl_object_name(s->a, pgm ? pgm : cmd_end), true, line);
    } else if (CMD_IS("SBMJOB")) {
        const char *cmd = cl_keyword(up, "CMD");
        if (cmd) {
            while (isspace((unsigned char)*cmd)) {
                cmd++;
            }
            if (strncmp(cmd, "CALL", 4) == 0 && !cl_name_char(cmd[4])) {
                const char *pgm = cl_keyword(cmd, "PGM");
                cl_call(s, cl_object_name(s->a, pgm ? pgm : cmd + 4), true, line);
            }
        }
    } else if (CMD_IS("CALLPRC")) {
        const char *prc = cl_keyword(up, "PRC");
        const char *name = cl_object_name(s->a, prc ? prc : cmd_end);
        cl_call(s, name, false, line);
    } else if (CMD_IS("DCLF") || CMD_IS("OPNQRYF") || CMD_IS("DSPFD") || CMD_IS("DSPFFD")) {
        if (!CMD_IS("DSPFD") && !CMD_IS("DSPFFD")) {
            cl_file(s,
                    cl_object_name(s->a, cl_keyword(up, "FILE") ? cl_keyword(up, "FILE") : cmd_end),
                    false);
        }
    } else if (CMD_IS("OVRDBF")) {
        const char *to = cl_keyword(up, "TOFILE");
        cl_file(s, cl_object_name(s->a, to ? to : ""), false);
    } else if (CMD_IS("CPYF")) {
        const char *from = cl_keyword(up, "FROMFILE");
        const char *to = cl_keyword(up, "TOFILE");
        cl_file(s, from ? cl_object_name(s->a, from) : NULL, false);
        cl_file(s, to ? cl_object_name(s->a, to) : NULL, true);
    } else if (CMD_IS("CLRPFM") || CMD_IS("RGZPFM") || CMD_IS("ADDPFM")) {
        const char *f = cl_keyword(up, "FILE");
        cl_file(s, f ? cl_object_name(s->a, f) : NULL, true);
    } else if (CMD_IS("CPYFRMIMPF")) {
        const char *to = cl_keyword(up, "TOFILE");
        cl_file(s, to ? cl_object_name(s->a, to) : NULL, true);
    } else if (CMD_IS("CPYTOIMPF")) {
        const char *from = cl_keyword(up, "FROMFILE");
        cl_file(s, from ? cl_object_name(s->a, from) : NULL, false);
    } else if (CMD_IS("RUNQRY")) {
        const char *f = cl_keyword(up, "QRYFILE");
        cl_file(s, f ? cl_object_name(s->a, f) : NULL, false);
    }
#undef CMD_IS
}

/* ── statement assembly ───────────────────────────────────────────── */

static void cl_push(ClState *s, char ch) {
    if (s->stmt_len + 1 >= s->stmt_cap) {
        int cap = s->stmt_cap ? s->stmt_cap * 2 : CL_STMT_INITIAL;
        char *buf = cbm_arena_alloc(s->a, (size_t)cap);
        if (!buf) {
            return;
        }
        if (s->stmt_len > 0) {
            memcpy(buf, s->stmt, (size_t)s->stmt_len);
        }
        s->stmt = buf;
        s->stmt_cap = cap;
    }
    s->stmt[s->stmt_len++] = ch;
}

static void cl_doc_add(ClState *s, const char *t, int len) {
    if (s->doc_closed) {
        return;
    }
    int from = 0;
    while (from < len && (isspace((unsigned char)t[from]) || t[from] == '*')) {
        from++;
    }
    int to = len;
    while (to > from && (isspace((unsigned char)t[to - 1]) || t[to - 1] == '*')) {
        to--;
    }
    bool has_text = false;
    for (int i = from; i < to; i++) {
        if (isalnum((unsigned char)t[i])) {
            has_text = true;
            break;
        }
    }
    if (!has_text || s->doc_len + (to - from) + 2 > CL_DOC_MAX) {
        return;
    }
    if (s->doc_len > 0) {
        s->doc[s->doc_len++] = '\n';
    }
    memcpy(s->doc + s->doc_len, t + from, (size_t)(to - from));
    s->doc_len += to - from;
}

static void cl_finish(ClState *s) {
    while (s->stmt_len > 0 && isspace((unsigned char)s->stmt[s->stmt_len - 1])) {
        s->stmt_len--;
    }
    if (s->stmt_len > 0) {
        s->stmt[s->stmt_len] = '\0';
        s->doc_closed = true;
        cl_statement(s, s->stmt, s->stmt_line);
    }
    s->stmt_len = 0;
    s->skip_blanks = false;
}

/* One source line: strip block comments (which may span lines), then append
 * to the statement, ending it unless the line ends with `+` or `-`. */
static void cl_line(ClState *s, const char *t, int len, uint32_t line) {
    char *clean = cbm_arena_alloc(s->a, (size_t)len + 1);
    if (!clean) {
        return;
    }
    int n = 0;
    for (int i = 0; i < len; i++) {
        if (s->in_comment) {
            if (t[i] == '*' && i + 1 < len && t[i + 1] == '/') {
                s->in_comment = false;
                i++;
            }
            continue;
        }
        if (t[i] == '/' && i + 1 < len && t[i + 1] == '*') {
            /* comment: keep its text as docstring material while no statement was seen */
            int j = i + 2;
            int end = len;
            for (int k = j; k + 1 < len; k++) {
                if (t[k] == '*' && t[k + 1] == '/') {
                    end = k;
                    break;
                }
            }
            cl_doc_add(s, t + j, end - j);
            if (end == len) {
                s->in_comment = true;
                break;
            }
            i = end + 1;
            continue;
        }
        if (t[i] == '\'') {
            /* copy a quoted literal verbatim (a comment marker inside it is text) */
            clean[n++] = t[i];
            i++;
            while (i < len && t[i] != '\'') {
                clean[n++] = t[i++];
            }
            if (i < len) {
                clean[n++] = t[i];
            }
            continue;
        }
        clean[n++] = t[i];
    }
    while (n > 0 && isspace((unsigned char)clean[n - 1])) {
        n--;
    }
    if (n == 0) {
        return;
    }
    int from = 0;
    if (s->skip_blanks || s->stmt_len == 0) {
        while (from < n && isspace((unsigned char)clean[from])) {
            from++;
        }
    }
    if (s->stmt_len == 0) {
        s->stmt_line = line;
    }
    s->skip_blanks = false;
    bool cont_plus = clean[n - 1] == '+';
    bool cont_minus = clean[n - 1] == '-';
    int to = (cont_plus || cont_minus) ? n - 1 : n;
    for (int i = from; i < to; i++) {
        cl_push(s, clean[i]);
    }
    if (cont_plus) {
        s->skip_blanks = true;
        return;
    }
    if (cont_minus) {
        return;
    }
    cl_finish(s);
}

/* ── entry ────────────────────────────────────────────────────────── */

void cbm_extract_cl(CBMExtractCtx *ctx) {
    ClState st;
    memset(&st, 0, sizeof(st));
    st.a = ctx->arena;
    st.result = ctx->result;
    st.rel_path = ctx->rel_path ? ctx->rel_path : "";
    st.module_qn = ctx->module_qn ? ctx->module_qn : "";

    const char *base = cl_basename(st.rel_path);
    const char *dot = strchr(base, '.');
    size_t n = dot ? (size_t)(dot - base) : strlen(base);
    char *program = cbm_arena_strndup(st.a, base, n);
    for (char *c = program; c && *c; c++) {
        *c = (char)toupper((unsigned char)*c);
    }
    st.program_qn = cbm_arena_sprintf(st.a, "%s.%s", st.module_qn, program);

    const char *src = ctx->source;
    int len = ctx->source_len;
    uint32_t total = 0;
    for (int i = 0; i < len; i++) {
        if (src[i] == '\n') {
            total++;
        }
    }
    if (len > 0 && src[len - 1] != '\n') {
        total++;
    }
    if (total == 0) {
        total = 1;
    }

    CBMDefinition mod;
    memset(&mod, 0, sizeof(mod));
    mod.name = st.rel_path;
    mod.qualified_name = st.module_qn;
    mod.label = "Module";
    mod.file_path = st.rel_path;
    mod.start_line = 1;
    mod.end_line = total;
    mod.lines = (int)total;
    mod.is_exported = true;
    mod.is_test = st.result->is_test_file;
    cbm_defs_push(&st.result->defs, st.a, mod);

    int pos = 0;
    uint32_t line = 0;
    while (pos < len) {
        int start = pos;
        while (pos < len && src[pos] != '\n') {
            pos++;
        }
        int llen = pos - start;
        if (llen > 0 && src[start + llen - 1] == '\r') {
            llen--;
        }
        pos++;
        line++;
        cl_line(&st, src + start, llen, line);
    }
    cl_finish(&st);

    CBMDefinition pgm;
    memset(&pgm, 0, sizeof(pgm));
    pgm.name = program;
    pgm.qualified_name = st.program_qn;
    pgm.label = "Function";
    pgm.file_path = st.rel_path;
    pgm.start_line = 1;
    pgm.end_line = total;
    pgm.lines = (int)total;
    pgm.is_exported = true;
    pgm.is_entry_point = true;
    pgm.return_type = cbm_ibmi_is_cl(base) && cl_ieq(strrchr(base, '.'), ".mnucmd") ? "menu" : "CL";
    pgm.docstring = st.doc_len ? cbm_arena_strndup(st.a, st.doc, (size_t)st.doc_len) : NULL;
    pgm.complexity = 1;
    cbm_defs_push(&st.result->defs, st.a, pgm);
}
