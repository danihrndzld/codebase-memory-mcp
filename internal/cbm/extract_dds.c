// extract_dds.c — IBM i DDS line scanner: PF, LF, DSPF, PRTF and ICFF source
// members (and their *38 forms), registered under CBM_LANG_RPG.
//
//   Module    one per file
//   Struct    the file object, named after the source member (return_type
//             PF / LF / DSPF / PRTF / ICFF); RPG F-specs and CL DCLF resolve
//             their READS / WRITES to it by name
//   Struct    one per record format (R), nested under the file; its docstring
//             is the format's TEXT() and, for a keyed format, "key: A, B"
//   Field     one per field of a format: type from length / data type /
//             decimals (char(60), zoned(7:0), packed(13:2)) or `ref` when the
//             field is defined by reference; docstring is TEXT() or COLHDG()
//   reads     a logical file reads its physical files (PFILE / JFILE): from
//             the file Struct to the physical file name
//   imports   PFILE / JFILE / REF / REFFLD targets, so the modules link too
//
// Columns (1-based): 6 `A` (optional; some exports leave it blank), 7 `*`
// comment, 17 name type (R format, K key, J join, S select, O omit), 19-28
// name, 29 `R` reference, 30-34 length, 35 data type, 36-37 decimals, 38
// usage, 39-41 row, 42-44 column, 45-80 keywords; a keyword line whose name
// and type are blank continues the previous entry (`+` at the end drops the
// next line's leading blanks, `-` continues as is). Constants (a quoted
// literal in the keyword area with no name) are not emitted.

#include "cbm.h"
#include "arena.h"
#include "foundation/constants.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
    DDS_COL_FORM = 5,    /* column 6 */
    DDS_COL_COMMENT = 6, /* column 7 */
    DDS_COL_NAMETYPE = 16,
    DDS_NAME_FROM = 18,
    DDS_NAME_TO = 28,
    DDS_COL_REF = 28,
    DDS_LEN_FROM = 29,
    DDS_LEN_TO = 34,
    DDS_COL_TYPE = 34,
    DDS_DEC_FROM = 35,
    DDS_DEC_TO = 37,
    DDS_COL_USAGE = 37,
    DDS_ROW_FROM = 38,
    DDS_ROW_TO = 41,
    DDS_COL_FROM = 41,
    DDS_COL_TO = 44,
    DDS_KW_FROM = 44,
    DDS_LINE_END = 80,
    DDS_DOC_MAX = 512,
    DDS_KW_INITIAL = 256,
    DDS_KEYS_MAX = 32,
    DDS_FIELDS_MAX = 4096,
};

typedef enum { ENT_NONE = 0, ENT_FILE, ENT_FORMAT, ENT_FIELD, ENT_OTHER } EntKind;

typedef struct {
    CBMArena *a;
    CBMFileResult *result;
    const char *rel_path;
    const char *module_qn;
    const char *kind;      /* PF, LF, DSPF, PRTF, ICFF */
    const char *file_name; /* upper-cased member name */
    const char *file_qn;
    int file_def; /* index of the file Struct in result->defs */
    bool file_doc_set;

    /* pending entity whose keywords may still continue */
    EntKind ent;
    const char *ent_name;
    uint32_t ent_line;
    const char *ent_len;
    char ent_type;
    const char *ent_dec;
    char ent_usage;
    bool ent_ref;
    const char *ent_row;
    const char *ent_col;
    char *kw;
    int kw_len;
    int kw_cap;

    /* current format */
    const char *fmt_name;
    const char *fmt_qn;
    int fmt_def; /* index in result->defs, -1 when none */
    const char *fmt_text;
    const char *keys[DDS_KEYS_MAX];
    int nkeys;
    const char *field_names[DDS_FIELDS_MAX];
    int field_defs[DDS_FIELDS_MAX];
    int nfields;

    char doc[DDS_DOC_MAX];
    int doc_len;
} DdsState;

/* ── helpers ──────────────────────────────────────────────────────── */

static const char *dds_basename(const char *path) {
    const char *base = path;
    for (const char *p = path; p && *p; p++) {
        if (*p == '/' || *p == '\\') {
            base = p + 1;
        }
    }
    return base;
}

static bool dds_ieq(const char *a, const char *b) {
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

static const char *dds_kind_for(const char *base) {
    const char *dot = base ? strrchr(base, '.') : NULL;
    if (!dot) {
        return NULL;
    }
    if (dds_ieq(dot, ".pf") || dds_ieq(dot, ".pf38")) {
        return "PF";
    }
    if (dds_ieq(dot, ".lf") || dds_ieq(dot, ".lf38")) {
        return "LF";
    }
    if (dds_ieq(dot, ".dspf") || dds_ieq(dot, ".dspf38")) {
        return "DSPF";
    }
    if (dds_ieq(dot, ".prtf") || dds_ieq(dot, ".prtf38")) {
        return "PRTF";
    }
    if (dds_ieq(dot, ".icff")) {
        return "ICFF";
    }
    return NULL;
}

bool cbm_ibmi_is_dds(const char *basename) {
    return dds_kind_for(basename) != NULL;
}

static char *dds_upper(CBMArena *a, const char *s) {
    char *out = cbm_arena_strdup(a, s);
    for (char *p = out; p && *p; p++) {
        *p = (char)toupper((unsigned char)*p);
    }
    return out;
}

static char *dds_trim(CBMArena *a, const char *t, int len) {
    int from = 0;
    while (from < len && isspace((unsigned char)t[from])) {
        from++;
    }
    int to = len;
    while (to > from && isspace((unsigned char)t[to - 1])) {
        to--;
    }
    if (to <= from) {
        return NULL;
    }
    return cbm_arena_strndup(a, t + from, (size_t)(to - from));
}

static char *dds_field(CBMArena *a, const char *t, int len, int from, int to) {
    if (from >= len) {
        return NULL;
    }
    if (to > len) {
        to = len;
    }
    return dds_trim(a, t + from, to - from);
}

static char dds_col(const char *t, int len, int col) {
    return col < len ? t[col] : ' ';
}

static bool dds_name_char(char c) {
    return isalnum((unsigned char)c) || c == '_' || c == '@' || c == '#' || c == '$';
}

/* The quoted string argument of KEYWORD('...') with '' unescaped, or NULL. */
static const char *dds_quoted_arg(CBMArena *a, const char *kw, const char *keyword) {
    size_t klen = strlen(keyword);
    for (const char *p = kw; (p = strstr(p, keyword)) != NULL; p += klen) {
        if (p != kw && dds_name_char(p[-1])) {
            continue;
        }
        const char *q = p + klen;
        while (*q == ' ') {
            q++;
        }
        if (*q != '\'') {
            continue;
        }
        q++;
        char *out = cbm_arena_alloc(a, strlen(q) + 1);
        int n = 0;
        while (*q) {
            if (*q == '\'') {
                if (q[1] == '\'') {
                    out[n++] = '\'';
                    q += 2;
                    continue;
                }
                break;
            }
            out[n++] = *q++;
        }
        while (n > 0 && isspace((unsigned char)out[n - 1])) {
            n--;
        }
        out[n] = '\0';
        return n ? out : NULL;
    }
    return NULL;
}

/* All quoted strings of COLHDG('a' 'b' ...) joined with blanks, or NULL. */
static const char *dds_colhdg(CBMArena *a, const char *kw) {
    const char *p = strstr(kw, "COLHDG(");
    if (!p) {
        return NULL;
    }
    p += 7;
    char *out = cbm_arena_alloc(a, strlen(p) + 1);
    int n = 0;
    while (*p && *p != ')') {
        if (*p == '\'') {
            p++;
            if (n > 0) {
                out[n++] = ' ';
            }
            while (*p && !(*p == '\'' && p[1] != '\'')) {
                if (*p == '\'' && p[1] == '\'') {
                    p++;
                }
                out[n++] = *p++;
            }
            if (*p == '\'') {
                p++;
            }
            continue;
        }
        p++;
    }
    out[n] = '\0';
    return n ? out : NULL;
}

/* The bare object names inside KEYWORD(...): a `LIB/` qualifier is dropped.
 * Fills up to `max` entries and returns the count. */
static int dds_names_in(CBMArena *a, const char *kw, const char *keyword, const char **out, int max,
                        int skip_first) {
    const char *p = strstr(kw, keyword);
    if (!p || (p != kw && dds_name_char(p[-1]))) {
        return 0;
    }
    p += strlen(keyword);
    int n = 0;
    int seen = 0;
    while (*p && *p != ')' && n < max) {
        while (*p == ' ') {
            p++;
        }
        const char *start = p;
        while (*p && *p != ' ' && *p != ')') {
            p++;
        }
        if (p == start) {
            break;
        }
        const char *slash = NULL;
        for (const char *q = start; q < p; q++) {
            if (*q == '/') {
                slash = q;
            }
        }
        const char *name = slash ? slash + 1 : start;
        if (seen++ < skip_first) {
            continue;
        }
        if (name[0] == '*' || name[0] == '&' || p == name) {
            continue;
        }
        out[n++] = dds_upper(a, cbm_arena_strndup(a, name, (size_t)(p - name)));
    }
    return n;
}

static const char *dds_type_text(CBMArena *a, const DdsState *s) {
    long len = s->ent_len ? strtol(s->ent_len, NULL, 10) : 0;
    long dec = s->ent_dec ? strtol(s->ent_dec, NULL, 10) : -1;
    switch (toupper((unsigned char)s->ent_type)) {
    case 'A':
        return len ? cbm_arena_sprintf(a, "char(%ld)", len) : "char";
    case 'S':
        return cbm_arena_sprintf(a, "zoned(%ld:%ld)", len, dec < 0 ? 0 : dec);
    case 'P':
        return cbm_arena_sprintf(a, "packed(%ld:%ld)", len, dec < 0 ? 0 : dec);
    case 'B':
        return cbm_arena_sprintf(a, "binary(%ld:%ld)", len, dec < 0 ? 0 : dec);
    case 'F':
        return cbm_arena_sprintf(a, "float(%ld)", len);
    case 'L':
        return "date";
    case 'T':
        return "time";
    case 'Z':
        return "timestamp";
    case 'N':
        return "ind";
    case 'Y':
        return cbm_arena_sprintf(a, "numeric(%ld:%ld)", len, dec < 0 ? 0 : dec);
    default:
        break;
    }
    if (len > 0 && dec >= 0) {
        return cbm_arena_sprintf(a, "zoned(%ld:%ld)", len, dec);
    }
    if (len > 0) {
        return cbm_arena_sprintf(a, "char(%ld)", len);
    }
    return s->ent_ref ? "ref" : NULL;
}

/* ── docstrings ───────────────────────────────────────────────────── */

static void dds_doc_add(DdsState *s, const char *t, int len) {
    int from = 0;
    while (from < len && (isspace((unsigned char)t[from]) || t[from] == '*' || t[from] == '-')) {
        from++;
    }
    /* SDA / RLU bookkeeping lines (%%TS, %%EC, %%FI, %%RI) are not documentation */
    if (from + 1 < len && t[from] == '%' && t[from + 1] == '%') {
        return;
    }
    int to = len;
    while (to > from &&
           (isspace((unsigned char)t[to - 1]) || t[to - 1] == '*' || t[to - 1] == '-')) {
        to--;
    }
    bool has_text = false;
    for (int i = from; i < to; i++) {
        if (isalnum((unsigned char)t[i])) {
            has_text = true;
            break;
        }
    }
    if (!has_text || s->doc_len + (to - from) + 2 > DDS_DOC_MAX) {
        return;
    }
    if (s->doc_len > 0) {
        s->doc[s->doc_len++] = '\n';
    }
    memcpy(s->doc + s->doc_len, t + from, (size_t)(to - from));
    s->doc_len += to - from;
}

static const char *dds_doc_take(DdsState *s) {
    if (s->doc_len == 0) {
        return NULL;
    }
    const char *d = cbm_arena_strndup(s->a, s->doc, (size_t)s->doc_len);
    s->doc_len = 0;
    return d;
}

/* ── keyword accumulator ──────────────────────────────────────────── */

static void kw_append(DdsState *s, const char *piece) {
    if (!piece) {
        return;
    }
    bool plus = s->kw_len > 0 && s->kw[s->kw_len - 1] == '+';
    bool minus = s->kw_len > 0 && s->kw[s->kw_len - 1] == '-';
    if (plus || minus) {
        s->kw_len--;
        if (plus) {
            while (*piece == ' ') {
                piece++;
            }
        }
    } else if (s->kw_len > 0) {
        piece = cbm_arena_sprintf(s->a, " %s", piece);
    }
    int n = (int)strlen(piece);
    if (s->kw_len + n + 1 > s->kw_cap) {
        int cap = s->kw_cap ? s->kw_cap : DDS_KW_INITIAL;
        while (cap < s->kw_len + n + 1) {
            cap *= 2;
        }
        char *buf = cbm_arena_alloc(s->a, (size_t)cap);
        if (!buf) {
            return;
        }
        if (s->kw_len > 0) {
            memcpy(buf, s->kw, (size_t)s->kw_len);
        }
        s->kw = buf;
        s->kw_cap = cap;
    }
    memcpy(s->kw + s->kw_len, piece, (size_t)n);
    s->kw_len += n;
    s->kw[s->kw_len] = '\0';
}

static const char *kw_text(DdsState *s) {
    if (s->kw_len == 0) {
        return "";
    }
    s->kw[s->kw_len] = '\0';
    return s->kw;
}

/* ── emission ─────────────────────────────────────────────────────── */

static CBMDefinition dds_def(const DdsState *s, const char *name, const char *qn, const char *label,
                             uint32_t start, uint32_t end) {
    CBMDefinition d;
    memset(&d, 0, sizeof(d));
    d.name = name;
    d.qualified_name = qn;
    d.label = label;
    d.file_path = s->rel_path;
    d.start_line = start;
    d.end_line = end < start ? start : end;
    d.lines = (int)(d.end_line - start + 1);
    d.is_exported = true;
    return d;
}

static void dds_import(DdsState *s, const char *name) {
    if (!name || dds_ieq(name, s->file_name)) {
        return;
    }
    CBMImport imp = {name, name};
    cbm_imports_push(&s->result->imports, s->a, imp);
}

static void dds_read(DdsState *s, const char *name) {
    if (!name || dds_ieq(name, s->file_name)) {
        return;
    }
    CBMReadWrite rw = {.var_name = name, .enclosing_func_qn = s->file_qn, .is_write = false};
    cbm_rw_push(&s->result->rw, s->a, rw);
}

/* File-level keywords: REF(file) is an import. */
static void dds_file_keywords(DdsState *s, const char *kw) {
    const char *names[4];
    int n = dds_names_in(s->a, kw, "REF(", names, 4, 0);
    for (int i = 0; i < n; i++) {
        dds_import(s, names[i]);
    }
}

/* Close the current format: patch its end line and its docstring with the
 * keys, and reset the per-format field list. */
static void dds_format_end(DdsState *s, uint32_t last_line) {
    if (s->fmt_def >= 0) {
        CBMDefinition *d = &s->result->defs.items[s->fmt_def];
        d->end_line = last_line < d->start_line ? d->start_line : last_line;
        d->lines = (int)(d->end_line - d->start_line + 1);
        if (s->nkeys > 0) {
            char *keys = cbm_arena_strdup(s->a, "");
            for (int i = 0; i < s->nkeys; i++) {
                keys = cbm_arena_sprintf(s->a, "%s%s%s", keys, i ? ", " : "", s->keys[i]);
            }
            d->docstring = d->docstring ? cbm_arena_sprintf(s->a, "%s\nkey: %s", d->docstring, keys)
                                        : cbm_arena_sprintf(s->a, "key: %s", keys);
            /* mark the key fields */
            for (int i = 0; i < s->nkeys; i++) {
                for (int f = 0; f < s->nfields; f++) {
                    if (dds_ieq(s->field_names[f], s->keys[i])) {
                        CBMDefinition *fd = &s->result->defs.items[s->field_defs[f]];
                        fd->docstring = fd->docstring ? cbm_arena_sprintf(s->a, "key %d. %s", i + 1,
                                                                          fd->docstring)
                                                      : cbm_arena_sprintf(s->a, "key %d", i + 1);
                    }
                }
            }
        }
    }
    s->fmt_def = -1;
    s->fmt_name = NULL;
    s->fmt_qn = NULL;
    s->fmt_text = NULL;
    s->nkeys = 0;
    s->nfields = 0;
}

/* Emit the pending entity now that its keywords are complete. */
static void dds_flush(DdsState *s, uint32_t last_line) {
    const char *kw = kw_text(s);
    switch (s->ent) {
    case ENT_FILE:
        dds_file_keywords(s, kw);
        break;
    case ENT_FORMAT: {
        dds_format_end(s, s->ent_line > 0 ? s->ent_line - 1 : 0);
        const char *text = dds_quoted_arg(s->a, kw, "TEXT(");
        const char *doc = dds_doc_take(s);
        CBMDefinition d =
            dds_def(s, s->ent_name, cbm_arena_sprintf(s->a, "%s.%s", s->file_qn, s->ent_name),
                    "Struct", s->ent_line, s->ent_line);
        d.parent_class = s->file_qn;
        d.return_type = "record format";
        d.docstring = text ? text : doc;
        s->fmt_name = s->ent_name;
        s->fmt_qn = d.qualified_name;
        s->fmt_text = text;
        s->fmt_def = s->result->defs.count;
        cbm_defs_push(&s->result->defs, s->a, d);
        if (!s->file_doc_set && s->file_def >= 0 && (text || doc)) {
            s->result->defs.items[s->file_def].docstring = text ? text : doc;
            s->file_doc_set = true;
        }
        /* a logical file's physical files; a join's files */
        const char *names[8];
        int n = dds_names_in(s->a, kw, "PFILE(", names, 8, 0);
        n += dds_names_in(s->a, kw, "JFILE(", names + n, 8 - n, 0);
        for (int i = 0; i < n; i++) {
            dds_read(s, names[i]);
            dds_import(s, names[i]);
        }
        const char *fmt[1];
        if (dds_names_in(s->a, kw, "FORMAT(", fmt, 1, 0) == 1) {
            dds_import(s, fmt[0]);
        }
        break;
    }
    case ENT_FIELD: {
        const char *owner_qn = s->fmt_qn ? s->fmt_qn : s->file_qn;
        const char *text = dds_quoted_arg(s->a, kw, "TEXT(");
        const char *colhdg = text ? NULL : dds_colhdg(s->a, kw);
        const char *doc = dds_doc_take(s);
        CBMDefinition d =
            dds_def(s, s->ent_name, cbm_arena_sprintf(s->a, "%s.%s", owner_qn, s->ent_name),
                    "Field", s->ent_line, s->ent_line);
        d.parent_class = owner_qn;
        d.return_type = dds_type_text(s->a, s);
        const char *reffld[2];
        if (dds_names_in(s->a, kw, "REFFLD(", reffld, 2, 1) == 1) {
            dds_import(s, reffld[0]);
            if (!d.return_type) {
                d.return_type = "ref";
            }
        }
        const char *use = NULL;
        if (s->ent_usage == 'B') {
            use = "both";
        } else if (s->ent_usage == 'I') {
            use = "input";
        } else if (s->ent_usage == 'O') {
            use = "output";
        } else if (s->ent_usage == 'H') {
            use = "hidden";
        }
        const char *base_doc = text ? text : (colhdg ? colhdg : doc);
        if (use && s->ent_row) {
            d.docstring = cbm_arena_sprintf(s->a, "%s%s%s (%s at %s,%s)", base_doc ? base_doc : "",
                                            base_doc ? " " : "", "", use, s->ent_row,
                                            s->ent_col ? s->ent_col : "");
        } else {
            d.docstring = base_doc;
        }
        if (s->nfields < DDS_FIELDS_MAX) {
            s->field_names[s->nfields] = s->ent_name;
            s->field_defs[s->nfields] = s->result->defs.count;
            s->nfields++;
        }
        cbm_defs_push(&s->result->defs, s->a, d);
        break;
    }
    case ENT_OTHER:
    case ENT_NONE:
        break;
    }
    s->ent = ENT_NONE;
    s->kw_len = 0;
    (void)last_line;
}

static void dds_begin(DdsState *s, EntKind kind, const char *name, uint32_t line) {
    dds_flush(s, line);
    s->ent = kind;
    s->ent_name = name;
    s->ent_line = line;
    s->ent_len = NULL;
    s->ent_type = ' ';
    s->ent_dec = NULL;
    s->ent_usage = ' ';
    s->ent_ref = false;
    s->ent_row = NULL;
    s->ent_col = NULL;
    s->kw_len = 0;
}

/* ── lines ────────────────────────────────────────────────────────── */

static void dds_line(DdsState *s, const char *t, int len, uint32_t line) {
    if (len > DDS_LINE_END) {
        len = DDS_LINE_END;
    }
    if (len <= DDS_COL_COMMENT) {
        return;
    }
    char form = dds_col(t, len, DDS_COL_FORM);
    if (form != 'A' && form != 'a' && form != ' ') {
        return;
    }
    if (form == ' ') {
        /* no form type: accept only when the sequence area is blank and the
         * line has DDS content, so a stray text line is not read as one */
        for (int i = 0; i < DDS_COL_FORM; i++) {
            if (!isspace((unsigned char)t[i])) {
                return;
            }
        }
    }
    char marker = dds_col(t, len, DDS_COL_COMMENT);
    if (marker == '*') {
        dds_doc_add(s, t + DDS_COL_COMMENT + 1, len - DDS_COL_COMMENT - 1);
        return;
    }
    char ntype = (char)toupper((unsigned char)dds_col(t, len, DDS_COL_NAMETYPE));
    const char *name = dds_field(s->a, t, len, DDS_NAME_FROM, DDS_NAME_TO);
    const char *kw = dds_field(s->a, t, len, DDS_KW_FROM, DDS_LINE_END);
    if (ntype == 'R' && name) {
        dds_begin(s, ENT_FORMAT, dds_upper(s->a, name), line);
        kw_append(s, kw);
        return;
    }
    if (ntype == 'K' && name) {
        dds_flush(s, line);
        if (s->nkeys < DDS_KEYS_MAX) {
            s->keys[s->nkeys++] = dds_upper(s->a, name);
        }
        s->ent = ENT_OTHER;
        return;
    }
    if (ntype == 'J' || ntype == 'S' || ntype == 'O') {
        dds_begin(s, ENT_OTHER, NULL, line);
        kw_append(s, kw);
        return;
    }
    if (name) {
        dds_begin(s, ENT_FIELD, dds_upper(s->a, name), line);
        s->ent_ref = toupper((unsigned char)dds_col(t, len, DDS_COL_REF)) == 'R';
        s->ent_len = dds_field(s->a, t, len, DDS_LEN_FROM, DDS_LEN_TO);
        s->ent_type = dds_col(t, len, DDS_COL_TYPE);
        s->ent_dec = dds_field(s->a, t, len, DDS_DEC_FROM, DDS_DEC_TO);
        s->ent_usage = (char)toupper((unsigned char)dds_col(t, len, DDS_COL_USAGE));
        s->ent_row = dds_field(s->a, t, len, DDS_ROW_FROM, DDS_ROW_TO);
        s->ent_col = dds_field(s->a, t, len, DDS_COL_FROM, DDS_COL_TO);
        kw_append(s, kw);
        return;
    }
    /* No name and no type: a constant (quoted literal with a position) or a
     * continuation of the previous entry's keywords. */
    if (kw && kw[0] == '\'' &&
        (dds_col(t, len, DDS_ROW_FROM) != ' ' || dds_col(t, len, DDS_ROW_FROM + 1) != ' ' ||
         dds_col(t, len, DDS_COL_FROM) != ' ' || dds_col(t, len, DDS_COL_FROM + 1) != ' ')) {
        if (s->ent != ENT_NONE) {
            dds_flush(s, line);
        }
        s->ent = ENT_OTHER;
        return;
    }
    if (s->ent == ENT_NONE) {
        s->ent = ENT_FILE; /* file-level keywords before the first format */
        s->ent_line = line;
    }
    kw_append(s, kw);
}

/* ── entry ────────────────────────────────────────────────────────── */

void cbm_extract_dds(CBMExtractCtx *ctx) {
    DdsState st;
    memset(&st, 0, sizeof(st));
    st.a = ctx->arena;
    st.result = ctx->result;
    st.rel_path = ctx->rel_path ? ctx->rel_path : "";
    st.module_qn = ctx->module_qn ? ctx->module_qn : "";
    st.fmt_def = -1;
    st.file_def = -1;

    const char *base = dds_basename(st.rel_path);
    st.kind = dds_kind_for(base);
    const char *dot = strchr(base, '.');
    size_t n = dot ? (size_t)(dot - base) : strlen(base);
    st.file_name = dds_upper(st.a, cbm_arena_strndup(st.a, base, n));
    st.file_qn = cbm_arena_sprintf(st.a, "%s.%s", st.module_qn, st.file_name);

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

    CBMDefinition mod = dds_def(&st, st.rel_path, st.module_qn, "Module", 1, total);
    mod.is_test = st.result->is_test_file;
    cbm_defs_push(&st.result->defs, st.a, mod);

    CBMDefinition file = dds_def(&st, st.file_name, st.file_qn, "Struct", 1, total);
    file.return_type = st.kind;
    st.file_def = st.result->defs.count;
    cbm_defs_push(&st.result->defs, st.a, file);

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
        dds_line(&st, src + start, llen, line);
    }
    dds_flush(&st, total);
    dds_format_end(&st, total);
    if (!st.file_doc_set && st.file_def >= 0) {
        const char *doc = dds_doc_take(&st);
        if (doc) {
            st.result->defs.items[st.file_def].docstring = doc;
        }
    }
}
