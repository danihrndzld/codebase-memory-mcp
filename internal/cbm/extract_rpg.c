// extract_rpg.c — IBM i RPG extractor: RPG II/III and RPG IV fixed-form,
// mixed fixed/free-form, and **FREE source.
//
// There is no tree-sitter grammar for RPG here. Fixed-form specifications are
// column-positional -- the specification letter is column 6, `*` in column 7
// marks a comment, and every field is a fixed column range -- and RPG II/III
// lay the calculation specification out differently from RPG IV. A line
// scanner with a small statement accumulator for free-form code is the natural
// parser for that, so this file does directly what the tree-sitter extractors
// do through node-type tables:
//
//   Module    one per file (the same Module def cbm_extract_definitions makes)
//   Function  the program (named after the source member), each procedure
//             (dcl-proc / P-spec) and each subroutine (begsr / BEGSR)
//   Struct    data structures, with one Field per subfield
//   Enum      dcl-enum, with one Field per member
//   Variable  module-level standalone fields (dcl-s / D-spec S) and named
//             constants (dcl-c / D-spec C)
//   calls     exsr / EXSR / CASxx, callp and bare prototyped calls, CALL and
//             CALLB with a literal target, `exec sql call`
//   imports   /copy and /include
//
// A prototype (dcl-pr / D-spec PR) is not a definition: it binds a local name
// to an external program (extpgm) or procedure (extproc), so a call through it
// is emitted against that external name. Program names are IBM i object names
// and always upper case; procedure names keep their source spelling.
//
// Subroutines nest under the procedure or program that owns them
// (module.PROGRAM.SUBR, module.proc.subr) and an exsr is emitted with that
// same tail, so the registry's same-module lookup lands on the exact def even
// when every program in the project has an *INZSR.
//
// Not covered: the 12-byte sequence/date prefix of raw source-member dumps
// (git exports strip it), CALL through a variable (a dynamic target), and
// table references in embedded SQL. RPG subscripts arrays with parentheses,
// so `rates(idx)` is only known to be a subscript when `rates` is declared in
// the same file; an array from a copybook is emitted as a call to `rates`,
// which the registry may then bind to that array's Variable node.

#include "cbm.h"
#include "arena.h"
#include "foundation/constants.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* 0-based column indexes of the fixed-form layout: column N is index N-1.
 * Every `_TO` is exclusive. */
enum {
    COL_SPEC = 5,      /* column 6: specification letter */
    COL_COMMENT = 6,   /* column 7: `*` comment or `/` directive */
    COL_LINE_END = 80, /* fixed-form content stops at column 80 */

    /* RPG IV definition specification (D). */
    D_NAME_FROM = 6,
    D_NAME_TO = 21,
    D_DEFTYPE_FROM = 23,
    D_DEFTYPE_TO = 25,
    D_FROM_FROM = 25,
    D_FROM_TO = 32,
    D_LEN_FROM = 32,
    D_LEN_TO = 39,
    D_TYPE_COL = 39,
    D_DEC_FROM = 40,
    D_DEC_TO = 42,
    D_KEYWORDS_FROM = 43,

    /* RPG IV procedure specification (P). */
    P_NAME_FROM = 6,
    P_NAME_TO = 21,
    P_BEGIN_END_COL = 23,
    P_KEYWORDS_FROM = 43,

    /* Control specification (H): keywords run from column 7. */
    H_KEYWORDS_FROM = 6,

    /* RPG IV calculation specification (C). */
    C4_FACTOR1_FROM = 11,
    C4_FACTOR1_TO = 25,
    C4_OPCODE_FROM = 25,
    C4_OPCODE_TO = 35,
    C4_FACTOR2_FROM = 35,
    C4_FACTOR2_TO = 49,
    C4_RESULT_FROM = 49,
    C4_RESULT_TO = 63,
    C4_EXTENDED_FROM = 35, /* extended factor 2 runs to COL_LINE_END */

    /* RPG II/III calculation specification (C). */
    C3_FACTOR1_FROM = 17,
    C3_FACTOR1_TO = 27,
    C3_OPCODE_FROM = 27,
    C3_OPCODE_TO = 32,
    C3_FACTOR2_FROM = 32,
    C3_FACTOR2_TO = 42,
    C3_RESULT_FROM = 42,
    C3_RESULT_TO = 48,

    ELLIPSIS_LEN = 3, /* `...` continues a long name on the next line */
    DECIMAL_BASE = 10,
    BLOCK_STACK_MAX = 64,
    DOCSTRING_MAX = 1024,
    STMT_INITIAL_CAP = 256,
    LIST_INITIAL_CAP = 16,
    BASE_COMPLEXITY = 1, /* cyclomatic complexity of a body with no decisions */
    NO_DECIMALS = -1,    /* D-spec decimal positions column left blank */
};

typedef enum {
    DIALECT_RPG_IV = 0, /* .rpgle .sqlrpgle .rpgleinc: D/P specs, free-form */
    DIALECT_RPG_III,    /* .rpg .rpg36 .rpg38 .sqlrpg .sqlrpg38: RPG II/III C-spec columns */
} RpgDialect;

/* Which multi-statement declaration the scanner is inside. */
typedef enum {
    DECL_NONE = 0,
    DECL_PI,   /* procedure interface: member lines are parameters */
    DECL_PR,   /* prototype: member lines are ignored */
    DECL_DS,   /* data structure: member lines are subfields */
    DECL_ENUM, /* enum: member lines are members */
} DeclKind;

typedef struct {
    const char **items;
    int count;
    int cap;
} StrList;

typedef struct {
    const char *local;    /* prototype name as written */
    const char *external; /* call target the prototype binds it to */
} Prototype;

typedef struct {
    Prototype *items;
    int count;
    int cap;
} PrototypeList;

/* Cyclomatic-style counters for one Function def. The block stack is only
 * needed by fixed-form code, where a bare END closes an IF, a DO or a CASxx
 * group alike and the loop depth must know which one it was. */
typedef struct {
    int complexity;
    int loop_count;
    int loop_depth;
    int open_loops;
    char blocks[BLOCK_STACK_MAX]; /* 'L' loop, 'B' any other block */
    int nblocks;
    bool last_was_cas; /* consecutive CASxx lines form one block */
} Metrics;

/* One Function def under construction: the program, a procedure or a
 * subroutine. */
typedef struct {
    bool active;
    const char *name;
    const char *qn;
    uint32_t start_line;
    uint32_t end_line;
    const char *docstring;
    const char *return_type;
    bool is_exported;
    StrList param_names;
    StrList param_types;
    Metrics metrics;
} FuncDef;

/* A Struct or Enum under construction. `emit` is false for one declared
 * inside a procedure (a local) and for an unnamed data structure, whose
 * subfields are module-level variables instead. */
typedef struct {
    bool active;
    bool emit;
    const char *label;
    const char *name;
    const char *qn;
    uint32_t start_line;
    uint32_t last_line;
    const char *docstring;
    bool is_exported;
} Container;

typedef struct {
    const char *callee;
    const char *enclosing_qn;
    uint32_t line;
    bool is_subroutine;   /* exsr / EXSR / CASxx target */
    bool maybe_subscript; /* `name(...)` in an expression: an array unless callable */
} CallSite;

typedef struct {
    CallSite *items;
    int count;
    int cap;
} CallList;

typedef struct {
    const char *name;
    const char *qn;
    const char *owner_qn; /* the procedure or program QN it nests under */
} SubrDef;

typedef struct {
    SubrDef *items;
    int count;
    int cap;
} SubrList;

typedef struct {
    CBMArena *a;
    CBMFileResult *result;
    const char *rel_path;
    const char *module_qn;
    RpgDialect dialect;
    bool fully_free; /* `**FREE` on line 1: columns carry no meaning */
    bool stop;       /* compile-time data (`**`) or /EOF reached */

    /* Names declared in this file that can never be call targets: an
     * `x(...)` on one of them is an array subscript. */
    StrList declared;
    PrototypeList prototypes;
    StrList proc_names; /* procedure names, for the exact spelling of a callee */
    SubrList subrs;
    CallList calls;

    /* Control options. */
    bool nomain;
    const char *linear_main; /* procedure named by ctl-opt main() */

    FuncDef program;
    const char *program_qn; /* NULL for a copybook */
    bool saw_main_statement;

    FuncDef proc;
    FuncDef subr;
    Container container;
    DeclKind decl;
    bool decl_fixed; /* the open declaration is a D-spec entry, not a dcl-* statement */

    /* Fixed-form: a `...` name continuation, and an extended factor 2 that
     * may span continuation lines. */
    const char *pending_name;
    char *pending_expr;
    int pending_expr_len;
    int pending_expr_cap;
    const char *pending_opcode;
    uint32_t pending_line;

    /* Free-form statement accumulator. */
    char *stmt;
    int stmt_len;
    int stmt_cap;
    uint32_t stmt_line;
    bool in_string;

    /* Comment lines immediately above a definition become its docstring. */
    char doc[DOCSTRING_MAX];
    int doc_len;
} RpgState;

/* ── Small string helpers ─────────────────────────────────────────── */

static bool is_name_start(char c) {
    return isalpha((unsigned char)c) || c == '_' || c == '@' || c == '#' || c == '$';
}

static bool is_name_char(char c) {
    return is_name_start(c) || isdigit((unsigned char)c);
}

static bool ieq(const char *a, const char *b) {
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

static bool istarts(const char *s, const char *prefix) {
    if (!s || !prefix) {
        return false;
    }
    while (*prefix) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) {
            return false;
        }
        s++;
        prefix++;
    }
    return true;
}

static bool ends_with_ellipsis(const char *s, size_t len) {
    return len > ELLIPSIS_LEN && memcmp(s + len - ELLIPSIS_LEN, "...", ELLIPSIS_LEN) == 0;
}

static char *dup_upper(CBMArena *a, const char *s) {
    char *out = cbm_arena_strdup(a, s);
    for (char *p = out; p && *p; p++) {
        *p = (char)toupper((unsigned char)*p);
    }
    return out;
}

/* Trimmed copy of t[0..len), or NULL when nothing but blanks remain. */
static char *dup_trim(CBMArena *a, const char *t, int len) {
    int from = 0;
    while (from < len && isspace((unsigned char)t[from])) {
        from++;
    }
    int to = len;
    while (to > from && isspace((unsigned char)t[to - SKIP_ONE])) {
        to--;
    }
    if (to <= from) {
        return NULL;
    }
    return cbm_arena_strndup(a, t + from, (size_t)(to - from));
}

/* Trimmed text of the fixed-form field at [from, to), clipped to the line. */
static char *field(CBMArena *a, const char *t, int len, int from, int to) {
    if (from >= len) {
        return NULL;
    }
    if (to > len) {
        to = len;
    }
    return dup_trim(a, t + from, to - from);
}

static char field_char(const char *t, int len, int col) {
    return col < len ? t[col] : ' ';
}

static bool is_blank(const char *t, int len) {
    for (int i = 0; i < len; i++) {
        if (!isspace((unsigned char)t[i])) {
            return false;
        }
    }
    return true;
}

static const char *path_basename(const char *path) {
    const char *base = path;
    for (const char *p = path; p && *p; p++) {
        if (*p == '/' || *p == '\\') {
            base = p + SKIP_ONE;
        }
    }
    return base;
}

/* Make room for one more element in an arena-backed list (the shape of
 * GROW_ARRAY in cbm.c). Returns from the caller when the arena is exhausted. */
#define RPG_GROW(list, arena)                                                                     \
    do {                                                                                          \
        if ((list)->count == (list)->cap) {                                                       \
            int new_cap = (list)->cap ? (list)->cap * PAIR_LEN : LIST_INITIAL_CAP;                \
            void *new_items = cbm_arena_alloc((arena), sizeof(*(list)->items) * (size_t)new_cap); \
            if (!new_items) {                                                                     \
                return;                                                                           \
            }                                                                                     \
            if ((list)->count > 0) {                                                              \
                memcpy(new_items, (list)->items, sizeof(*(list)->items) * (size_t)(list)->count); \
            }                                                                                     \
            (list)->items = new_items;                                                            \
            (list)->cap = new_cap;                                                                \
        }                                                                                         \
    } while (0)

static void list_push(CBMArena *a, StrList *l, const char *s) {
    RPG_GROW(l, a);
    l->items[l->count++] = s;
}

static const char *list_find_ieq(const StrList *l, const char *s) {
    for (int i = 0; i < l->count; i++) {
        if (ieq(l->items[i], s)) {
            return l->items[i];
        }
    }
    return NULL;
}

/* NULL-terminated copy for the CBMDefinition array fields, or NULL if empty. */
static const char **list_terminated(CBMArena *a, const StrList *l) {
    if (l->count == 0) {
        return NULL;
    }
    const char **out = cbm_arena_alloc(a, sizeof(*out) * (size_t)(l->count + SKIP_ONE));
    memcpy(out, l->items, sizeof(*out) * (size_t)l->count);
    out[l->count] = NULL;
    return out;
}

/* ── Word cursor over a statement ─────────────────────────────────── */

typedef struct {
    const char *p;
    const char *end;
} Cursor;

static Cursor cursor_of(const char *text) {
    Cursor c = {text, text + strlen(text)};
    return c;
}

/* Step over a string literal starting at its opening quote. A doubled quote
 * inside the literal is an escaped quote, not the end. */
static void skip_string(Cursor *c) {
    char quote = *c->p++;
    while (c->p < c->end) {
        if (*c->p != quote) {
            c->p++;
            continue;
        }
        c->p++;
        if (c->p < c->end && *c->p == quote) {
            c->p++;
            continue;
        }
        return;
    }
}

/* Advance past a balanced parenthesised group starting at `(`. */
static void skip_group(Cursor *c) {
    int depth = 0;
    while (c->p < c->end) {
        char ch = *c->p;
        if (ch == '\'' || ch == '"') {
            skip_string(c);
            continue;
        }
        c->p++;
        if (ch == '(') {
            depth++;
        } else if (ch == ')') {
            depth--;
            if (depth == 0) {
                return;
            }
        }
    }
}

static bool is_word_char(char c) {
    return is_name_char(c) || c == '-' || c == '*' || c == '.' || c == '%';
}

/* Skip blanks, punctuation, string literals and stray groups up to the next
 * word. Returns false at the end of the text. */
static bool cursor_to_word(Cursor *c) {
    while (c->p < c->end) {
        char ch = *c->p;
        if (ch == '\'' || ch == '"') {
            skip_string(c);
        } else if (ch == '(') {
            skip_group(c);
        } else if (is_word_char(ch)) {
            return true;
        } else {
            c->p++;
        }
    }
    return false;
}

/* Next word of the statement, with the `(...)` group glued to it when one
 * follows without a blank (`packed(15:2)`, `extpgm('X')`). Returns NULL at the
 * end. A word ending in `...` continues with the next word (long-name
 * continuation). */
static const char *next_word(CBMArena *a, Cursor *c, const char **group) {
    if (group) {
        *group = NULL;
    }
    char *word = NULL;
    for (;;) {
        if (!cursor_to_word(c)) {
            return word;
        }
        const char *start = c->p;
        while (c->p < c->end && is_word_char(*c->p)) {
            c->p++;
        }
        size_t len = (size_t)(c->p - start);
        bool continues = ends_with_ellipsis(start, len);
        size_t take = continues ? len - ELLIPSIS_LEN : len;
        word = word ? cbm_arena_sprintf(a, "%s%.*s", word, (int)take, start)
                    : cbm_arena_strndup(a, start, take);
        if (!continues) {
            break;
        }
    }
    if (group && c->p < c->end && *c->p == '(') {
        const char *gstart = c->p;
        skip_group(c);
        *group = cbm_arena_strndup(a, gstart, (size_t)(c->p - gstart));
    }
    return word;
}

/* Whether any remaining word of the cursor equals `kw`. The cursor itself is
 * passed by value and left where it was. */
static bool words_contain(CBMArena *a, Cursor c, const char *kw) {
    const char *w = NULL;
    while ((w = next_word(a, &c, NULL)) != NULL) {
        if (ieq(w, kw)) {
            return true;
        }
    }
    return false;
}

/* The text inside a `(...)` group, without the parentheses and blanks. */
static char *group_inner(CBMArena *a, const char *group) {
    if (!group || group[0] != '(') {
        return NULL;
    }
    size_t len = strlen(group);
    if (len < PAIR_LEN) {
        return NULL;
    }
    return dup_trim(a, group + SKIP_ONE, (int)(len - PAIR_LEN));
}

/* A quoted `'name'` loses its quotes; an unquoted object name is upper-cased
 * when `upper_bare` says so (the compiler does the same). `*CWIDEN:'name'`
 * and other `prefix:name` forms keep only the last part; a `LIB/NAME`
 * qualification keeps only the object. */
static const char *external_name(CBMArena *a, const char *inner, bool upper_bare) {
    if (!inner || !inner[0]) {
        return NULL;
    }
    const char *colon = strrchr(inner, ':');
    if (colon) {
        inner = dup_trim(a, colon + SKIP_ONE, (int)strlen(colon + SKIP_ONE));
        if (!inner) {
            return NULL;
        }
    }
    size_t len = strlen(inner);
    bool quoted = (inner[0] == '\'' || inner[0] == '"') && len >= PAIR_LEN &&
                  inner[len - SKIP_ONE] == inner[0];
    const char *name = quoted ? cbm_arena_strndup(a, inner + SKIP_ONE, len - PAIR_LEN) : inner;
    const char *slash = strrchr(name, '/');
    if (slash) {
        name = slash + SKIP_ONE;
    }
    if (!name[0]) {
        return NULL;
    }
    return (!quoted && upper_bare) ? dup_upper(a, name) : cbm_arena_strdup(a, name);
}

/* ── Vocabulary ───────────────────────────────────────────────────── */

/* Free-form words that are never a procedure call even when a `(` follows:
 * operation codes (which take extenders such as `chain(e)`), control words and
 * the boolean operators. */
static bool is_reserved_word(const char *w) {
    static const char *const words[] = {
        "acq",     "and",     "begsr",    "call",      "callb",   "callp",    "chain",   "clear",
        "close",   "commit",  "data-gen", "data-into", "dealloc", "delete",   "dou",     "dow",
        "dsply",   "dump",    "else",     "elseif",    "enddo",   "endfor",   "endif",   "endmon",
        "endsl",   "endsr",   "eval",     "eval-corr", "evalr",   "except",   "exec",    "exfmt",
        "exsr",    "feod",    "for",      "for-each",  "force",   "if",       "in",      "iter",
        "leave",   "leavesr", "monitor",  "next",      "not",     "on-error", "on-exit", "open",
        "or",      "other",   "out",      "post",      "read",    "readc",    "reade",   "readp",
        "readpe",  "reset",   "return",   "rolbk",     "select",  "setgt",    "setll",   "sort",
        "sorta",   "sql",     "test",     "unlock",    "update",  "when",     "write",   "xml-into",
        "xml-sax", NULL};
    for (const char *const *p = words; *p; p++) {
        if (ieq(w, *p)) {
            return true;
        }
    }
    return false;
}

/* Free-form data type keywords: the word after a name that describes it. */
static bool is_type_word(const char *w) {
    static const char *const types[] = {
        "char",    "varchar", "ucs2", "varucs2", "graph",   "vargraph", "ind",  "packed",
        "zoned",   "bindec",  "int",  "uns",     "float",   "date",     "time", "timestamp",
        "pointer", "object",  "like", "likeds",  "likerec", "likefile", NULL};
    for (const char *const *p = types; *p; p++) {
        if (ieq(w, *p)) {
            return true;
        }
    }
    return false;
}

/* Statement openers that end an implicit member run (a DS whose end-ds is
 * missing, a PI whose end-pi is missing). */
static bool is_decl_opener(const char *op) {
    return ieq(op, "dcl-proc") || ieq(op, "dcl-pi") || ieq(op, "dcl-pr") || ieq(op, "dcl-ds") ||
           ieq(op, "dcl-s") || ieq(op, "dcl-c") || ieq(op, "dcl-f") || ieq(op, "dcl-enum") ||
           ieq(op, "ctl-opt");
}

static bool is_decl_closer(const char *op) {
    return ieq(op, "end-pi") || ieq(op, "end-pr") || ieq(op, "end-ds") || ieq(op, "end-enum") ||
           ieq(op, "end-proc");
}

/* Fixed-form opcodes whose operand is an expression in the extended factor 2
 * (columns 36-80, continued on following lines with a blank opcode). */
static bool is_extended_opcode(const char *op) {
    return ieq(op, "EVAL") || ieq(op, "EVALR") || ieq(op, "EVAL-CORR") || ieq(op, "IF") ||
           ieq(op, "ELSEIF") || ieq(op, "WHEN") || ieq(op, "DOW") || ieq(op, "DOU") ||
           ieq(op, "FOR") || ieq(op, "RETURN") || ieq(op, "CALLP") || ieq(op, "ON-ERROR") ||
           ieq(op, "SORTA");
}

static bool is_condition_word(const char *op) {
    return ieq(op, "if") || ieq(op, "elseif") || ieq(op, "when") || ieq(op, "dow") ||
           ieq(op, "dou");
}

/* ── Docstrings and metrics ───────────────────────────────────────── */

static void doc_reset(RpgState *s) {
    s->doc_len = 0;
}

/* Append one comment line. Lines with no letter or digit are banners
 * (`*-----`) and are dropped. */
static void doc_add(RpgState *s, const char *t, int len) {
    int from = 0;
    while (from < len && isspace((unsigned char)t[from])) {
        from++;
    }
    int to = len;
    while (to > from && isspace((unsigned char)t[to - SKIP_ONE])) {
        to--;
    }
    bool has_text = false;
    for (int i = from; i < to; i++) {
        if (isalnum((unsigned char)t[i])) {
            has_text = true;
            break;
        }
    }
    if (!has_text) {
        return;
    }
    int n = to - from;
    if (s->doc_len + n + PAIR_LEN > DOCSTRING_MAX) {
        return;
    }
    if (s->doc_len > 0) {
        s->doc[s->doc_len++] = '\n';
    }
    memcpy(s->doc + s->doc_len, t + from, (size_t)n);
    s->doc_len += n;
}

static const char *doc_take(RpgState *s) {
    if (s->doc_len == 0) {
        return NULL;
    }
    const char *d = cbm_arena_strndup(s->a, s->doc, (size_t)s->doc_len);
    s->doc_len = 0;
    return d;
}

static void metrics_init(Metrics *m) {
    memset(m, 0, sizeof(*m));
    m->complexity = BASE_COMPLEXITY;
}

static void metrics_branch(Metrics *m) {
    m->complexity++;
}

static void metrics_push(Metrics *m, char kind) {
    if (m->nblocks < BLOCK_STACK_MAX) {
        m->blocks[m->nblocks] = kind;
    }
    m->nblocks++;
}

static void metrics_loop_open(Metrics *m) {
    m->complexity++;
    m->loop_count++;
    m->open_loops++;
    if (m->open_loops > m->loop_depth) {
        m->loop_depth = m->open_loops;
    }
    metrics_push(m, 'L');
}

static void metrics_block_open(Metrics *m) {
    metrics_push(m, 'B');
}

/* Close the innermost block; a loop leaves the loop nesting. */
static void metrics_close(Metrics *m) {
    if (m->nblocks == 0) {
        return;
    }
    m->nblocks--;
    if (m->nblocks < BLOCK_STACK_MAX && m->blocks[m->nblocks] == 'L' && m->open_loops > 0) {
        m->open_loops--;
    }
}

/* Every `and` / `or` in a condition is one more decision. */
static int count_and_or(CBMArena *a, const char *text) {
    int n = 0;
    Cursor c = cursor_of(text);
    const char *w = NULL;
    while ((w = next_word(a, &c, NULL)) != NULL) {
        if (ieq(w, "and") || ieq(w, "or")) {
            n++;
        }
    }
    return n;
}

static Metrics *current_metrics(RpgState *s) {
    if (s->subr.active) {
        return &s->subr.metrics;
    }
    if (s->proc.active) {
        return &s->proc.metrics;
    }
    return &s->program.metrics;
}

/* ── Scopes ───────────────────────────────────────────────────────── */

/* True when main-line code belongs to a program Function def. A nomain
 * module has no main line, a linear-main module runs its named procedure. */
static bool has_cycle_main(const RpgState *s) {
    return s->program_qn && !s->nomain && !s->linear_main;
}

/* QN that a statement at this point is attributed to. */
static const char *enclosing_qn(const RpgState *s) {
    if (s->subr.active) {
        return s->subr.qn;
    }
    if (s->proc.active) {
        return s->proc.qn;
    }
    return has_cycle_main(s) ? s->program_qn : s->module_qn;
}

/* QN a new subroutine nests under. */
static const char *owner_qn(const RpgState *s) {
    if (s->proc.active) {
        return s->proc.qn;
    }
    return has_cycle_main(s) ? s->program_qn : s->module_qn;
}

static CBMDefinition def_base(const RpgState *s, const char *name, const char *qn,
                              const char *label, uint32_t start, uint32_t end) {
    CBMDefinition d;
    memset(&d, 0, sizeof(d));
    d.name = name;
    d.qualified_name = qn;
    d.label = label;
    d.file_path = s->rel_path;
    d.start_line = start;
    d.end_line = end < start ? start : end;
    d.lines = (int)(d.end_line - start + SKIP_ONE);
    return d;
}

static const char *build_signature(CBMArena *a, const FuncDef *f) {
    if (f->param_names.count == 0) {
        return NULL;
    }
    char *sig = cbm_arena_strdup(a, "(");
    for (int i = 0; i < f->param_names.count; i++) {
        const char *type = f->param_types.items[i];
        sig = cbm_arena_sprintf(a, "%s%s%s%s%s", sig, i > 0 ? ", " : "", f->param_names.items[i],
                                type[0] ? " " : "", type);
    }
    return cbm_arena_sprintf(a, "%s)", sig);
}

static void emit_function(RpgState *s, FuncDef *f, uint32_t end_line, bool entry_point) {
    CBMDefinition d = def_base(s, f->name, f->qn, "Function", f->start_line, end_line);
    d.docstring = f->docstring;
    d.return_type = f->return_type;
    d.is_exported = f->is_exported;
    d.is_entry_point = entry_point;
    d.signature = build_signature(s->a, f);
    d.param_names = list_terminated(s->a, &f->param_names);
    d.param_types = list_terminated(s->a, &f->param_types);
    d.param_count = f->param_names.count;
    d.complexity = f->metrics.complexity;
    d.loop_count = f->metrics.loop_count;
    d.loop_depth = f->metrics.loop_depth;
    cbm_defs_push(&s->result->defs, s->a, d);
    f->active = false;
}

static void func_begin(FuncDef *f, const char *name, const char *qn, uint32_t line, bool exported,
                       const char *doc) {
    memset(f, 0, sizeof(*f));
    f->active = true;
    f->name = name;
    f->qn = qn;
    f->start_line = line;
    f->is_exported = exported;
    f->docstring = doc;
    metrics_init(&f->metrics);
}

static void subr_end(RpgState *s, uint32_t line) {
    if (s->subr.active) {
        emit_function(s, &s->subr, line, false);
    }
}

static void proc_end(RpgState *s, uint32_t line) {
    subr_end(s, line);
    if (s->proc.active) {
        emit_function(s, &s->proc, line, false);
    }
}

static void subr_begin(RpgState *s, const char *name, uint32_t line, const char *doc) {
    subr_end(s, line - SKIP_ONE); /* a BEGSR without ENDSR ends at the next BEGSR */
    const char *owner = owner_qn(s);
    const char *qn = cbm_arena_sprintf(s->a, "%s.%s", owner, name);
    SubrList *l = &s->subrs;
    RPG_GROW(l, s->a);
    func_begin(&s->subr, name, qn, line, false, doc);
    SubrDef sd = {name, qn, owner};
    l->items[l->count++] = sd;
}

static void decl_end(RpgState *s);

static void proc_begin(RpgState *s, const char *name, uint32_t line, bool exported,
                       const char *doc) {
    decl_end(s);
    proc_end(s, line - SKIP_ONE);
    const char *qn = cbm_arena_sprintf(s->a, "%s.%s", s->module_qn, name);
    func_begin(&s->proc, name, qn, line, exported, doc);
    list_push(s->a, &s->proc_names, name);
}

/* An executable statement outside every procedure is main-line code: the
 * program def spans the first to the last of them. */
static void mark_executable(RpgState *s, uint32_t line) {
    if (s->proc.active) {
        return;
    }
    s->saw_main_statement = true;
    if (s->program.start_line == 0) {
        s->program.start_line = line;
    }
    s->program.end_line = line;
}

/* ── Declarations ─────────────────────────────────────────────────── */

static void container_close(RpgState *s) {
    Container *c = &s->container;
    if (!c->active) {
        return;
    }
    c->active = false;
    if (!c->emit) {
        return;
    }
    CBMDefinition d = def_base(s, c->name, c->qn, c->label, c->start_line, c->last_line);
    d.docstring = c->docstring;
    d.is_exported = c->is_exported;
    cbm_defs_push(&s->result->defs, s->a, d);
}

static void decl_end(RpgState *s) {
    container_close(s);
    s->decl = DECL_NONE;
    s->decl_fixed = false;
}

static void container_begin(RpgState *s, const char *label, const char *name, uint32_t line,
                            bool exported, const char *doc) {
    decl_end(s);
    Container *c = &s->container;
    memset(c, 0, sizeof(*c));
    c->active = true;
    c->label = label;
    c->start_line = line;
    c->last_line = line;
    c->docstring = doc;
    c->is_exported = exported;
    bool named = name && !ieq(name, "*n");
    if (named) {
        c->name = name;
        c->qn = cbm_arena_sprintf(s->a, "%s.%s", s->module_qn, name);
        list_push(s->a, &s->declared, name);
    }
    c->emit = named && !s->proc.active;
}

static void container_end(RpgState *s, uint32_t line) {
    s->container.last_line = line;
    decl_end(s);
}

static void push_named_def(RpgState *s, const char *label, const char *name, const char *qn,
                           uint32_t line, const char *type, const char *parent, bool exported) {
    CBMDefinition d = def_base(s, name, qn, label, line, line);
    d.return_type = type;
    d.parent_class = parent;
    d.is_exported = exported;
    cbm_defs_push(&s->result->defs, s->a, d);
}

/* A standalone field or named constant: a Variable when module-level. */
static void module_variable(RpgState *s, const char *name, uint32_t line, const char *type,
                            bool exported) {
    if (!name || ieq(name, "*n")) {
        return;
    }
    list_push(s->a, &s->declared, name);
    if (s->proc.active) {
        return;
    }
    const char *qn = cbm_arena_sprintf(s->a, "%s.%s", s->module_qn, name);
    push_named_def(s, "Variable", name, qn, line, type, NULL, exported);
}

/* A subfield or enum member. Under a named module-level container it is a
 * Field of it; under an unnamed module-level data structure it is a plain
 * Variable; inside a procedure it is a local and only its name is kept. */
static void member_field(RpgState *s, const char *name, const char *type, uint32_t line) {
    Container *c = &s->container;
    c->last_line = line;
    if (!name || ieq(name, "*n")) {
        return;
    }
    list_push(s->a, &s->declared, name);
    if (s->proc.active || !c->active) {
        return;
    }
    if (c->emit) {
        const char *qn = cbm_arena_sprintf(s->a, "%s.%s", c->qn, name);
        push_named_def(s, "Field", name, qn, line, type, c->qn, c->is_exported);
        return;
    }
    if (!c->name) {
        const char *qn = cbm_arena_sprintf(s->a, "%s.%s", s->module_qn, name);
        push_named_def(s, "Variable", name, qn, line, type, NULL, c->is_exported);
    }
}

/* A procedure-interface parameter belongs to the open procedure, or to the
 * program when the PI is the main procedure's. */
static void param_add(RpgState *s, const char *name, const char *type) {
    if (!name || ieq(name, "*n")) {
        return;
    }
    FuncDef *f = s->proc.active ? &s->proc : &s->program;
    list_push(s->a, &f->param_names, name);
    list_push(s->a, &f->param_types, type ? type : "");
    list_push(s->a, &s->declared, name);
}

static void prototype_add(RpgState *s, const char *local, const char *external) {
    PrototypeList *l = &s->prototypes;
    RPG_GROW(l, s->a);
    Prototype p = {local, external};
    l->items[l->count++] = p;
}

/* The external target named by an extpgm / extproc keyword in `keywords`, or
 * NULL when neither is present. A bare extpgm names the prototype itself,
 * upper-cased as the compiler does; a bare extproc keeps the spelling. */
static const char *prototype_keyword_target(CBMArena *a, const char *keywords, const char *name) {
    Cursor c = cursor_of(keywords);
    const char *group = NULL;
    const char *w = NULL;
    while ((w = next_word(a, &c, &group)) != NULL) {
        if (ieq(w, "extpgm")) {
            const char *ext = external_name(a, group_inner(a, group), true);
            return ext ? ext : dup_upper(a, name);
        }
        if (ieq(w, "extproc")) {
            const char *ext = external_name(a, group_inner(a, group), false);
            return ext ? ext : name;
        }
    }
    return NULL;
}

/* ── Calls ────────────────────────────────────────────────────────── */

static void call_add(RpgState *s, const char *callee, uint32_t line, bool is_subroutine,
                     bool maybe_subscript) {
    if (!callee || !callee[0]) {
        return;
    }
    CallList *l = &s->calls;
    RPG_GROW(l, s->a);
    CallSite cs = {callee, enclosing_qn(s), line, is_subroutine, maybe_subscript};
    l->items[l->count++] = cs;
}

/* The word ending at `end` whose start is `start`, or the hyphenated opcode it
 * is the tail of: `xml-into(e)` is the opcode xml-into, not a call to `into`. */
static bool is_reserved_at(RpgState *s, const char *text, const char *start, const char *end) {
    if (is_reserved_word(cbm_arena_strndup(s->a, start, (size_t)(end - start)))) {
        return true;
    }
    if (start == text || start[-SKIP_ONE] != '-') {
        return false;
    }
    const char *word = start;
    while (word > text && (word[-SKIP_ONE] == '-' || is_name_char(word[-SKIP_ONE]))) {
        word--;
    }
    return is_reserved_word(cbm_arena_strndup(s->a, word, (size_t)(end - word)));
}

/* Every `name(` in an expression is a call candidate unless the name is a
 * built-in function (`%name`), a qualified subfield (`ds.name`), a special
 * value (`*in`), or a reserved word. Whether it is really an array subscript is
 * decided once every declaration in the file is known. */
static void scan_calls(RpgState *s, const char *text, uint32_t line) {
    Cursor c = cursor_of(text);
    char prev = ' ';
    while (c.p < c.end) {
        char ch = *c.p;
        if (ch == '\'' || ch == '"') {
            skip_string(&c);
            prev = ch;
            continue;
        }
        if (!is_name_start(ch) || is_name_char(prev) || prev == '%' || prev == '.' || prev == '*') {
            prev = ch;
            c.p++;
            continue;
        }
        const char *start = c.p;
        while (c.p < c.end && is_name_char(*c.p)) {
            c.p++;
        }
        prev = c.p[-SKIP_ONE];
        const char *q = c.p;
        while (q < c.end && *q == ' ') {
            q++;
        }
        if (q < c.end && *q == '(' && !is_reserved_at(s, text, start, c.p)) {
            call_add(s, cbm_arena_strndup(s->a, start, (size_t)(c.p - start)), line, false, true);
        }
    }
}

/* `exec sql call PROC(...)`: the stored procedure is an IBM i object, so an
 * unquoted name is upper-cased and a schema qualifier dropped. */
static void sql_call(RpgState *s, const char *text, uint32_t line) {
    Cursor c = cursor_of(text);
    const char *w = NULL;
    while ((w = next_word(s->a, &c, NULL)) != NULL) {
        if (!ieq(w, "call")) {
            continue;
        }
        const char *target = next_word(s->a, &c, NULL);
        if (!target) {
            return;
        }
        const char *dot = strrchr(target, '.');
        call_add(s, dup_upper(s->a, dot ? dot + SKIP_ONE : target), line, false, false);
        return;
    }
}

/* CALL 'PGM' / CALLB 'proc': only a literal names a target; a variable is a
 * dynamic call with no static target. */
static void literal_call(RpgState *s, const char *factor2, uint32_t line, bool is_program) {
    if (!factor2 || (factor2[0] != '\'' && factor2[0] != '"')) {
        return;
    }
    call_add(s, external_name(s->a, factor2, is_program), line, false, false);
}

/* A subroutine's exsr resolves to the def in the same procedure or main line
 * first, then to any subroutine of that name in the file. The callee is the
 * def's QN tail (`PROGRAM.SUBR`), which the registry's same-module lookup
 * matches exactly. */
static const char *resolve_subroutine(const RpgState *s, const CallSite *cs) {
    const char *owner = cs->enclosing_qn;
    for (int i = 0; i < s->subrs.count; i++) {
        if (strcmp(s->subrs.items[i].qn, cs->enclosing_qn) == 0) {
            owner = s->subrs.items[i].owner_qn; /* a call from inside a sibling */
            break;
        }
    }
    const SubrDef *found = NULL;
    for (int i = 0; i < s->subrs.count; i++) {
        const SubrDef *sd = &s->subrs.items[i];
        if (!ieq(sd->name, cs->callee)) {
            continue;
        }
        if (strcmp(sd->owner_qn, owner) == 0) {
            found = sd;
            break;
        }
        if (!found) {
            found = sd;
        }
    }
    if (!found) {
        return cs->callee;
    }
    size_t prefix = strlen(s->module_qn);
    if (strncmp(found->qn, s->module_qn, prefix) == 0 && found->qn[prefix] == '.') {
        return found->qn + prefix + SKIP_ONE;
    }
    return found->qn;
}

static const char *resolve_callee(const RpgState *s, const CallSite *cs) {
    if (cs->is_subroutine) {
        return resolve_subroutine(s, cs);
    }
    if (cs->maybe_subscript && list_find_ieq(&s->declared, cs->callee)) {
        return NULL; /* an array element, not a call */
    }
    for (int i = 0; i < s->prototypes.count; i++) {
        if (ieq(s->prototypes.items[i].local, cs->callee)) {
            return s->prototypes.items[i].external;
        }
    }
    const char *proc = list_find_ieq(&s->proc_names, cs->callee);
    return proc ? proc : cs->callee;
}

static void resolve_calls(RpgState *s) {
    for (int i = 0; i < s->calls.count; i++) {
        const CallSite *cs = &s->calls.items[i];
        const char *callee = resolve_callee(s, cs);
        if (!callee) {
            continue;
        }
        CBMCall call;
        memset(&call, 0, sizeof(call));
        call.callee_name = callee;
        call.enclosing_func_qn = cs->enclosing_qn;
        call.start_line = (int)cs->line;
        cbm_calls_push(&s->result->calls, s->a, call);
    }
}

/* ── Directives ───────────────────────────────────────────────────── */

/* `/copy` and `/include` name a source member as `[LIB/]FILE,MEMBER` or a
 * bare `MEMBER` (the compiler then assumes QRPGLESRC), or an IFS path: quoted,
 * or bare when it has a `/` and no `,`. The import's module path is
 * `FILE/MEMBER` (the library is not a directory in a git checkout) or the IFS
 * path as written, so it resolves like any other path-shaped import, and the
 * pipeline's sibling-file fallback still finds a copybook kept next to the
 * importer. Anything after the first blank is a comment. */
static void copy_directive(RpgState *s, const char *p, const char *end) {
    while (p < end && isspace((unsigned char)*p)) {
        p++;
    }
    if (p >= end) {
        return;
    }
    const char *module_path = NULL;
    const char *member = NULL;
    if (*p == '\'' || *p == '"') {
        char quote = *p++;
        const char *q = p;
        while (q < end && *q != quote) {
            q++;
        }
        if (q == p) {
            return;
        }
        module_path = cbm_arena_strndup(s->a, p, (size_t)(q - p));
        member = path_basename(module_path);
    } else {
        const char *q = p;
        while (q < end && !isspace((unsigned char)*q)) {
            q++;
        }
        char *token = cbm_arena_strndup(s->a, p, (size_t)(q - p));
        char *comma = strchr(token, ',');
        if (comma) {
            *comma = '\0';
            member = comma + SKIP_ONE;
            module_path = cbm_arena_sprintf(s->a, "%s/%s", path_basename(token), member);
        } else if (strchr(token, '/')) {
            module_path = token;
            member = path_basename(token);
        } else {
            member = token;
            module_path = cbm_arena_sprintf(s->a, "QRPGLESRC/%s", token);
        }
    }
    if (!member[0]) {
        return;
    }
    const char *dot = strchr(member, '.');
    const char *local = dot ? cbm_arena_strndup(s->a, member, (size_t)(dot - member)) : member;
    CBMImport imp = {local, module_path};
    cbm_imports_push(&s->result->imports, s->a, imp);
}

/* `text` starts at the `/`. */
static void directive(RpgState *s, const char *text, int len) {
    Cursor c = {text + SKIP_ONE, text + len};
    const char *word = next_word(s->a, &c, NULL);
    if (!word) {
        return;
    }
    if (ieq(word, "copy") || ieq(word, "include")) {
        copy_directive(s, c.p, c.end);
    } else if (ieq(word, "eof")) {
        s->stop = true;
    }
    /* /free, /end-free, /if, /define, /title, /eject, /space: no structure. */
}

/* ctl-opt / H-spec keywords that change what the main line is. */
static void control_options(RpgState *s, const char *text) {
    Cursor c = cursor_of(text);
    const char *group = NULL;
    const char *w = NULL;
    while ((w = next_word(s->a, &c, &group)) != NULL) {
        if (ieq(w, "nomain")) {
            s->nomain = true;
        } else if (ieq(w, "main") && group) {
            s->linear_main = group_inner(s->a, group);
        }
    }
}

/* ── Free-form statements ─────────────────────────────────────────── */

/* The type that follows a name, glued to its `(...)`, or NULL. */
static const char *type_after(CBMArena *a, Cursor *c) {
    Cursor probe = *c;
    const char *group = NULL;
    const char *w = next_word(a, &probe, &group);
    if (!w || !is_type_word(w)) {
        return NULL;
    }
    *c = probe;
    return group ? cbm_arena_sprintf(a, "%s%s", w, group) : w;
}

/* A line inside dcl-pi / dcl-pr / dcl-ds / dcl-enum: `name type keywords;`,
 * optionally introduced by dcl-parm or dcl-subf. */
static void free_member(RpgState *s, const char *op, Cursor *c, uint32_t line) {
    const char *name = op;
    if (ieq(op, "dcl-subf") || ieq(op, "dcl-parm")) {
        name = next_word(s->a, c, NULL);
    }
    const char *type = type_after(s->a, c);
    switch (s->decl) {
    case DECL_PI:
        param_add(s, name, type);
        break;
    case DECL_DS:
    case DECL_ENUM:
        member_field(s, name, type, line);
        break;
    case DECL_PR:
    case DECL_NONE:
        break;
    }
}

static void free_closer(RpgState *s, const char *op, uint32_t line) {
    if (ieq(op, "end-ds") || ieq(op, "end-enum")) {
        container_end(s, line);
    } else if (ieq(op, "end-proc")) {
        decl_end(s);
        proc_end(s, line);
    } else {
        s->decl = DECL_NONE;
    }
}

static void free_dcl_pi(RpgState *s, Cursor *c) {
    next_word(s->a, c, NULL); /* *n or the procedure name */
    FuncDef *f = s->proc.active ? &s->proc : &s->program;
    f->return_type = type_after(s->a, c);
    if (!words_contain(s->a, *c, "end-pi")) {
        s->decl = DECL_PI;
    }
}

static void free_dcl_pr(RpgState *s, Cursor *c) {
    const char *name = next_word(s->a, c, NULL);
    if (!name) {
        return;
    }
    type_after(s->a, c);
    const char *external = prototype_keyword_target(s->a, c->p, name);
    prototype_add(s, name, external ? external : name);
    if (!words_contain(s->a, *c, "end-pr")) {
        s->decl = DECL_PR;
    }
}

/* A `dcl-ds` with likeds/likerec is complete in one statement; otherwise
 * end-ds closes it, possibly on the same line. */
static void free_dcl_ds(RpgState *s, Cursor *c, uint32_t line, const char *doc) {
    const char *name = next_word(s->a, c, NULL);
    container_begin(s, "Struct", name, line, words_contain(s->a, *c, "export"), doc);
    if (words_contain(s->a, *c, "likeds") || words_contain(s->a, *c, "likerec") ||
        words_contain(s->a, *c, "end-ds")) {
        container_end(s, line);
        return;
    }
    s->decl = DECL_DS;
}

static void free_dcl_enum(RpgState *s, Cursor *c, uint32_t line, const char *doc) {
    const char *name = next_word(s->a, c, NULL);
    container_begin(s, "Enum", name, line, false, doc);
    if (words_contain(s->a, *c, "end-enum")) {
        container_end(s, line);
        return;
    }
    s->decl = DECL_ENUM;
}

/* Returns true when `op` opened a declaration statement. */
static bool free_declaration(RpgState *s, const char *op, Cursor *c, uint32_t line,
                             const char *doc) {
    if (ieq(op, "ctl-opt")) {
        control_options(s, c->p);
    } else if (ieq(op, "dcl-proc")) {
        const char *name = next_word(s->a, c, NULL);
        if (name) {
            proc_begin(s, name, line, words_contain(s->a, *c, "export"), doc);
        }
    } else if (ieq(op, "dcl-pi")) {
        free_dcl_pi(s, c);
    } else if (ieq(op, "dcl-pr")) {
        free_dcl_pr(s, c);
    } else if (ieq(op, "dcl-ds")) {
        free_dcl_ds(s, c, line, doc);
    } else if (ieq(op, "dcl-enum")) {
        free_dcl_enum(s, c, line, doc);
    } else if (ieq(op, "dcl-s")) {
        const char *name = next_word(s->a, c, NULL);
        const char *type = type_after(s->a, c);
        module_variable(s, name, line, type, words_contain(s->a, *c, "export"));
    } else if (ieq(op, "dcl-c")) {
        module_variable(s, next_word(s->a, c, NULL), line, NULL, false);
    } else if (!ieq(op, "dcl-f") && !ieq(op, "dcl-subf") && !ieq(op, "dcl-parm")) {
        return false;
    }
    return true;
}

static void free_executable(RpgState *s, const char *op, Cursor *c, const char *text, uint32_t line,
                            const char *doc) {
    Metrics *m = current_metrics(s);
    if (ieq(op, "begsr")) {
        const char *name = next_word(s->a, c, NULL);
        if (name) {
            subr_begin(s, name, line, doc);
        }
    } else if (ieq(op, "endsr")) {
        subr_end(s, line);
    } else if (ieq(op, "exsr")) {
        call_add(s, next_word(s->a, c, NULL), line, true, false);
    } else if (ieq(op, "callp")) {
        call_add(s, next_word(s->a, c, NULL), line, false, false);
    } else if (ieq(op, "exec")) {
        sql_call(s, text, line);
    } else if (is_condition_word(op)) {
        if (ieq(op, "dow") || ieq(op, "dou")) {
            metrics_loop_open(m);
        } else {
            metrics_branch(m);
        }
        m->complexity += count_and_or(s->a, c->p);
        scan_calls(s, text, line);
    } else if (ieq(op, "for") || ieq(op, "for-each")) {
        metrics_loop_open(m);
        scan_calls(s, text, line);
    } else if (ieq(op, "on-error")) {
        metrics_branch(m);
    } else if (ieq(op, "enddo") || ieq(op, "endfor")) {
        metrics_close(m);
    } else {
        scan_calls(s, text, line);
    }
    mark_executable(s, line);
}

static void free_statement(RpgState *s, const char *text, uint32_t line) {
    Cursor c = cursor_of(text);
    const char *op = next_word(s->a, &c, NULL);
    if (!op) {
        return;
    }
    const char *doc = doc_take(s);
    if (s->decl != DECL_NONE) {
        if (is_decl_closer(op)) {
            free_closer(s, op, line);
            return;
        }
        if (!is_decl_opener(op)) {
            free_member(s, op, &c, line);
            return;
        }
        decl_end(s); /* the previous declaration was never closed */
    }
    if (is_decl_closer(op)) {
        free_closer(s, op, line);
        return;
    }
    if (free_declaration(s, op, &c, line, doc)) {
        return;
    }
    free_executable(s, op, &c, text, line, doc);
}

static void stmt_push(RpgState *s, char ch) {
    if (s->stmt_len + SKIP_ONE >= s->stmt_cap) {
        int cap = s->stmt_cap ? s->stmt_cap * PAIR_LEN : STMT_INITIAL_CAP;
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

static void stmt_finish(RpgState *s) {
    while (s->stmt_len > 0 && isspace((unsigned char)s->stmt[s->stmt_len - SKIP_ONE])) {
        s->stmt_len--;
    }
    if (s->stmt_len == 0) {
        return;
    }
    s->stmt[s->stmt_len] = '\0';
    free_statement(s, s->stmt, s->stmt_line);
    s->stmt_len = 0;
}

/* Append t[from..len) to the statement accumulator. A statement ends at `;`
 * outside a string literal; `//` outside a literal starts a comment that runs
 * to the end of the line. */
static void free_feed_chars(RpgState *s, const char *t, int from, int len, uint32_t line) {
    for (int i = from; i < len; i++) {
        char ch = t[i];
        if (!s->in_string && ch == '/' && i + SKIP_ONE < len && t[i + SKIP_ONE] == '/') {
            return;
        }
        if (s->stmt_len == 0) {
            if (isspace((unsigned char)ch)) {
                continue;
            }
            s->stmt_line = line;
        }
        if (ch == '\'') {
            s->in_string = !s->in_string;
        }
        if (ch == ';' && !s->in_string) {
            stmt_finish(s);
            continue;
        }
        stmt_push(s, ch);
    }
}

/* Feed one line of free-form text (the whole line in **FREE source; from
 * column 7 in mixed source, where that column is blank because `*` or `/` in
 * it is a comment or a directive) to the statement accumulator. A directive or
 * a comment stands alone on its line. */
static void free_feed(RpgState *s, const char *t, int len, uint32_t line) {
    if (s->fully_free && len >= PAIR_LEN && t[0] == '*' && t[SKIP_ONE] == '*') {
        s->stop = true; /* **CTDATA and the compile-time data after it */
        return;
    }
    int i = 0;
    while (i < len && isspace((unsigned char)t[i])) {
        i++;
    }
    bool between_statements = s->stmt_len == 0 && !s->in_string;
    if (i >= len) {
        if (between_statements) {
            doc_reset(s);
        }
        return;
    }
    if (between_statements && t[i] == '/' && i + SKIP_ONE < len) {
        if (isalpha((unsigned char)t[i + SKIP_ONE])) {
            directive(s, t + i, len - i);
            return;
        }
        if (t[i + SKIP_ONE] == '/') {
            doc_add(s, t + i + PAIR_LEN, len - i - PAIR_LEN);
            return;
        }
    }
    free_feed_chars(s, t, i, len, line);
    if (s->stmt_len > 0) {
        stmt_push(s, ' '); /* the statement continues on the next line */
    }
}

/* ── Fixed-form specifications ────────────────────────────────────── */

/* A name ending in `...` is continued on the next specification line. Returns
 * true when this line carried only a fragment. */
static bool name_continues(RpgState *s, const char *name) {
    if (!name) {
        return false;
    }
    size_t n = strlen(name);
    if (!ends_with_ellipsis(name, n)) {
        return false;
    }
    char *head = cbm_arena_strndup(s->a, name, n - ELLIPSIS_LEN);
    s->pending_name =
        s->pending_name ? cbm_arena_sprintf(s->a, "%s%s", s->pending_name, head) : head;
    return true;
}

static const char *take_pending_name(RpgState *s, const char *name) {
    if (!s->pending_name) {
        return name;
    }
    const char *full =
        name ? cbm_arena_sprintf(s->a, "%s%s", s->pending_name, name) : s->pending_name;
    s->pending_name = NULL;
    return full;
}

/* A D-spec entry with no type or length takes its type from a LIKE, LIKEDS or
 * LIKEREC keyword; the keyword and its operand are the type text. */
static const char *like_keyword_type(CBMArena *a, const char *keywords) {
    if (!keywords) {
        return NULL;
    }
    Cursor c = cursor_of(keywords);
    const char *group = NULL;
    const char *w = NULL;
    while ((w = next_word(a, &c, &group)) != NULL) {
        if (group && (ieq(w, "like") || ieq(w, "likeds") || ieq(w, "likerec"))) {
            return cbm_arena_sprintf(a, "%s%s", w, group);
        }
    }
    return NULL;
}

/* Render the data type of a D-spec entry in free-form spelling from its type
 * column, length (or from/to positions), decimals and keywords. A blank type
 * with decimals is packed for a standalone field and zoned for a subfield. */
static const char *fixed_type(CBMArena *a, char type, const char *length, const char *from,
                              const char *dec, const char *keywords, bool in_ds) {
    long len = length ? strtol(length, NULL, DECIMAL_BASE) : 0;
    if (from && length) {
        long f = strtol(from, NULL, DECIMAL_BASE);
        if (len >= f) {
            len = len - f + SKIP_ONE;
        }
    }
    long d = dec ? strtol(dec, NULL, DECIMAL_BASE) : NO_DECIMALS;
    bool varying = keywords && words_contain(a, cursor_of(keywords), "varying");
    switch (toupper((unsigned char)type)) {
    case 'A':
        return cbm_arena_sprintf(a, varying ? "varchar(%ld)" : "char(%ld)", len);
    case 'P':
        return cbm_arena_sprintf(a, "packed(%ld:%ld)", len, d < 0 ? 0 : d);
    case 'S':
        return cbm_arena_sprintf(a, "zoned(%ld:%ld)", len, d < 0 ? 0 : d);
    case 'B':
        return cbm_arena_sprintf(a, "bindec(%ld:%ld)", len, d < 0 ? 0 : d);
    case 'I':
        return cbm_arena_sprintf(a, "int(%ld)", len);
    case 'U':
        return cbm_arena_sprintf(a, "uns(%ld)", len);
    case 'F':
        return cbm_arena_sprintf(a, "float(%ld)", len);
    case 'C':
        return cbm_arena_sprintf(a, "ucs2(%ld)", len);
    case 'G':
        return cbm_arena_sprintf(a, "graph(%ld)", len);
    case 'N':
        return "ind";
    case 'D':
        return "date";
    case 'T':
        return "time";
    case 'Z':
        return "timestamp";
    case '*':
        return "pointer";
    case 'O':
        return "object";
    default:
        break;
    }
    if (len > 0 && d >= 0) {
        return cbm_arena_sprintf(a, in_ds ? "zoned(%ld:%ld)" : "packed(%ld:%ld)", len, d);
    }
    if (len > 0) {
        return cbm_arena_sprintf(a, "char(%ld)", len);
    }
    return like_keyword_type(a, keywords);
}

/* A D-spec line with blank name, definition type, positions and type is a
 * continuation of the previous entry's keywords. EXTPGM / EXTPROC on such a
 * line still binds the prototype above it. */
static void fixed_d_continuation(RpgState *s, const char *keywords) {
    if (!keywords || s->decl != DECL_PR || s->prototypes.count == 0) {
        return;
    }
    Prototype *p = &s->prototypes.items[s->prototypes.count - SKIP_ONE];
    const char *external = prototype_keyword_target(s->a, keywords, p->local);
    if (external) {
        p->external = external;
    }
}

/* A D-spec line with a blank definition type is a member of the open entry:
 * a parameter of the PI, a subfield of the DS, or a parameter of the PR. */
static void fixed_d_member(RpgState *s, const char *name, const char *type, uint32_t line) {
    switch (s->decl) {
    case DECL_PI:
        param_add(s, name, type);
        break;
    case DECL_DS:
        member_field(s, name, type, line);
        break;
    case DECL_PR:
    case DECL_ENUM:
    case DECL_NONE:
        break;
    }
}

static void fixed_d_spec(RpgState *s, const char *t, int len, uint32_t line) {
    const char *name = field(s->a, t, len, D_NAME_FROM, D_NAME_TO);
    if (name_continues(s, name)) {
        return;
    }
    name = take_pending_name(s, name);
    const char *deftype = field(s->a, t, len, D_DEFTYPE_FROM, D_DEFTYPE_TO);
    const char *from = field(s->a, t, len, D_FROM_FROM, D_FROM_TO);
    const char *length = field(s->a, t, len, D_LEN_FROM, D_LEN_TO);
    char type = field_char(t, len, D_TYPE_COL);
    const char *dec = field(s->a, t, len, D_DEC_FROM, D_DEC_TO);
    const char *keywords = field(s->a, t, len, D_KEYWORDS_FROM, COL_LINE_END);
    if (!name && !deftype && !from && !length && type == ' ' && !dec) {
        fixed_d_continuation(s, keywords);
        return;
    }
    const char *doc = doc_take(s); /* after the continuations, which belong to an earlier entry */
    const char *typetext = fixed_type(s->a, type, length, from, dec, keywords, s->decl == DECL_DS);
    if (!deftype) {
        fixed_d_member(s, name, typetext, line);
        return;
    }
    decl_end(s);
    bool exported = keywords && words_contain(s->a, cursor_of(keywords), "export");
    if (ieq(deftype, "PR") && name) {
        const char *external = keywords ? prototype_keyword_target(s->a, keywords, name) : NULL;
        prototype_add(s, name, external ? external : name);
        s->decl = DECL_PR;
    } else if (ieq(deftype, "PI")) {
        FuncDef *f = s->proc.active ? &s->proc : &s->program;
        f->return_type = typetext;
        s->decl = DECL_PI;
    } else if (ieq(deftype, "DS")) {
        container_begin(s, "Struct", name, line, exported, doc);
        s->decl = DECL_DS;
    } else if (ieq(deftype, "S") || ieq(deftype, "C")) {
        module_variable(s, name, line, typetext, exported);
    }
    s->decl_fixed = s->decl != DECL_NONE;
}

static void fixed_p_spec(RpgState *s, const char *t, int len, uint32_t line) {
    const char *name = field(s->a, t, len, P_NAME_FROM, P_NAME_TO);
    if (name_continues(s, name)) {
        return;
    }
    name = take_pending_name(s, name);
    const char *doc = doc_take(s);
    char kind = (char)toupper((unsigned char)field_char(t, len, P_BEGIN_END_COL));
    if (kind == 'B' && name) {
        const char *keywords = field(s->a, t, len, P_KEYWORDS_FROM, COL_LINE_END);
        bool exported = keywords && words_contain(s->a, cursor_of(keywords), "export");
        proc_begin(s, name, line, exported, doc);
    } else if (kind == 'E') {
        decl_end(s);
        proc_end(s, line);
    }
}

/* Extended factor 2 accumulator (fixed-form expressions). */
static void pending_append(RpgState *s, const char *ext) {
    if (!ext) {
        return;
    }
    int n = (int)strlen(ext);
    if (s->pending_expr_len + n + PAIR_LEN > s->pending_expr_cap) {
        int cap = s->pending_expr_cap ? s->pending_expr_cap : STMT_INITIAL_CAP;
        while (cap < s->pending_expr_len + n + PAIR_LEN) {
            cap *= PAIR_LEN;
        }
        char *buf = cbm_arena_alloc(s->a, (size_t)cap);
        if (!buf) {
            return;
        }
        if (s->pending_expr_len > 0) {
            memcpy(buf, s->pending_expr, (size_t)s->pending_expr_len);
        }
        s->pending_expr = buf;
        s->pending_expr_cap = cap;
    }
    if (s->pending_expr_len > 0) {
        s->pending_expr[s->pending_expr_len++] = ' ';
    }
    memcpy(s->pending_expr + s->pending_expr_len, ext, (size_t)n);
    s->pending_expr_len += n;
}

static void pending_flush(RpgState *s) {
    if (!s->pending_opcode) {
        return;
    }
    if (s->pending_expr_len > 0) {
        s->pending_expr[s->pending_expr_len] = '\0';
        const char *expr = s->pending_expr;
        if (ieq(s->pending_opcode, "CALLP")) {
            Cursor c = cursor_of(expr);
            call_add(s, next_word(s->a, &c, NULL), s->pending_line, false, false);
        } else {
            scan_calls(s, expr, s->pending_line);
        }
        if (is_condition_word(s->pending_opcode)) {
            current_metrics(s)->complexity += count_and_or(s->a, expr);
        }
    }
    s->pending_opcode = NULL;
    s->pending_expr_len = 0;
}

static void pending_begin(RpgState *s, const char *opcode, const char *ext, uint32_t line) {
    s->pending_opcode = opcode;
    s->pending_line = line;
    s->pending_expr_len = 0;
    pending_append(s, ext);
}

/* BEGSR / ENDSR / EXSR / CALL / CALLB / CASxx: opcodes that define or call.
 * Returns true when handled. */
static bool fixed_c_structural(RpgState *s, const char *op, const char *f1, const char *f2,
                               const char *result, uint32_t line, const char *doc) {
    if (ieq(op, "BEGSR")) {
        if (f1) {
            subr_begin(s, f1, line, doc);
        }
        return true;
    }
    if (ieq(op, "ENDSR")) {
        subr_end(s, line);
        return true;
    }
    if (ieq(op, "EXSR")) {
        call_add(s, f2, line, true, false);
        return true;
    }
    if (ieq(op, "CALL") || ieq(op, "CALLB")) {
        literal_call(s, f2, line, ieq(op, "CALL"));
        return true;
    }
    if (istarts(op, "CAS")) {
        Metrics *m = current_metrics(s);
        if (!m->last_was_cas) {
            metrics_block_open(m);
        }
        m->last_was_cas = true;
        metrics_branch(m);
        call_add(s, result, line, true, false);
        return true;
    }
    return false;
}

/* Structured-operation opcodes and their xx-conditioned forms (IFEQ, DOWLT,
 * WHGT, ANDEQ...). */
static void fixed_c_metrics(RpgState *s, const char *op) {
    Metrics *m = current_metrics(s);
    if (istarts(op, "IF")) {
        metrics_branch(m);
        metrics_block_open(m);
    } else if (ieq(op, "ELSEIF") || istarts(op, "WH") || istarts(op, "AND") || istarts(op, "OR") ||
               ieq(op, "ON-ERROR")) {
        metrics_branch(m);
    } else if (istarts(op, "DOW") || istarts(op, "DOU") || ieq(op, "DO") || ieq(op, "FOR")) {
        metrics_loop_open(m);
    } else if (ieq(op, "SELEC") || ieq(op, "SELECT") || ieq(op, "MONITOR")) {
        metrics_block_open(m);
    } else if (istarts(op, "END")) {
        metrics_close(m);
    }
}

static void fixed_c_spec(RpgState *s, const char *t, int len, uint32_t line) {
    bool iv = s->dialect == DIALECT_RPG_IV;
    const char *f1 = iv ? field(s->a, t, len, C4_FACTOR1_FROM, C4_FACTOR1_TO)
                        : field(s->a, t, len, C3_FACTOR1_FROM, C3_FACTOR1_TO);
    const char *op = iv ? field(s->a, t, len, C4_OPCODE_FROM, C4_OPCODE_TO)
                        : field(s->a, t, len, C3_OPCODE_FROM, C3_OPCODE_TO);
    const char *f2 = iv ? field(s->a, t, len, C4_FACTOR2_FROM, C4_FACTOR2_TO)
                        : field(s->a, t, len, C3_FACTOR2_FROM, C3_FACTOR2_TO);
    const char *result = iv ? field(s->a, t, len, C4_RESULT_FROM, C4_RESULT_TO)
                            : field(s->a, t, len, C3_RESULT_FROM, C3_RESULT_TO);
    const char *ext = iv ? field(s->a, t, len, C4_EXTENDED_FROM, COL_LINE_END) : NULL;
    if (!op) {
        if (s->pending_opcode && !f1) {
            pending_append(s, ext); /* continuation of the extended factor 2 */
        }
        return;
    }
    pending_flush(s);
    decl_end(s);
    const char *doc = doc_take(s);
    char *opcode = dup_upper(s->a, op);
    char *paren = strchr(opcode, '(');
    if (paren) {
        *paren = '\0'; /* drop the extender: CALLP(E) -> CALLP */
    }
    if (!istarts(opcode, "CAS")) {
        current_metrics(s)->last_was_cas = false; /* any other opcode ends a CASxx group */
    }
    mark_executable(s, line);
    if (fixed_c_structural(s, opcode, f1, f2, result, line, doc)) {
        return;
    }
    if (is_extended_opcode(opcode)) {
        pending_begin(s, opcode, ext, line);
    }
    fixed_c_metrics(s, opcode);
}

/* One line of fixed-form or mixed source. */
static void fixed_line(RpgState *s, const char *t, int len, uint32_t line) {
    if (len >= PAIR_LEN && t[0] == '*' && t[SKIP_ONE] == '*') {
        s->stop = true; /* compile-time data follows */
        return;
    }
    if (len > COL_LINE_END) {
        len = COL_LINE_END; /* columns 81+ are comments */
    }
    if (is_blank(t, len)) {
        if (s->stmt_len == 0) {
            doc_reset(s);
        }
        return;
    }
    char spec = (char)toupper((unsigned char)field_char(t, len, COL_SPEC));
    char marker = field_char(t, len, COL_COMMENT);
    if (marker == '*') {
        doc_add(s, t + COL_COMMENT + SKIP_ONE, len - COL_COMMENT - SKIP_ONE);
        return;
    }
    if (marker == '/') {
        pending_flush(s);
        directive(s, t + COL_COMMENT, len - COL_COMMENT);
        return;
    }
    if (spec == ' ') {
        /* Free-form code. A D-spec entry cannot continue into it; a free-form
         * declaration in progress (dcl-ds ... end-ds across lines) can. */
        pending_flush(s);
        s->pending_name = NULL;
        if (s->decl_fixed) {
            decl_end(s);
        }
        if (len > COL_COMMENT) {
            free_feed(s, t + COL_COMMENT, len - COL_COMMENT, line);
        }
        return;
    }
    s->stmt_len = 0; /* a specification cannot interrupt a free-form statement */
    s->in_string = false;
    if (spec != 'C') {
        pending_flush(s);
    }
    if (spec != 'D' && spec != 'P') {
        s->pending_name = NULL; /* a `...` continuation only crosses D and P lines */
    }
    switch (spec) {
    case 'H': {
        const char *keywords = field(s->a, t, len, H_KEYWORDS_FROM, COL_LINE_END);
        if (keywords) {
            control_options(s, keywords);
        }
        doc_reset(s);
        break;
    }
    case 'D':
        if (s->dialect == DIALECT_RPG_IV) {
            fixed_d_spec(s, t, len, line);
        }
        break;
    case 'P':
        if (s->dialect == DIALECT_RPG_IV) {
            fixed_p_spec(s, t, len, line);
        }
        break;
    case 'C':
        fixed_c_spec(s, t, len, line);
        break;
    default: /* F, I, O, E, L: files, records and tables carry no structure */
        decl_end(s);
        doc_reset(s);
        break;
    }
}

/* ── File level ───────────────────────────────────────────────────── */

static bool is_free_marker(const char *t, int len) {
    static const char marker[] = "**free";
    int mlen = (int)sizeof(marker) - SKIP_ONE;
    if (len < mlen || !istarts(t, marker)) {
        return false;
    }
    return is_blank(t + mlen, len - mlen);
}

static bool path_has_ext(const char *base, const char *ext) {
    const char *dot = strrchr(base, '.');
    return dot && ieq(dot, ext);
}

static RpgDialect dialect_for(const char *base) {
    if (path_has_ext(base, ".rpg") || path_has_ext(base, ".rpg36") ||
        path_has_ext(base, ".rpg38") || path_has_ext(base, ".sqlrpg") ||
        path_has_ext(base, ".sqlrpg38")) {
        return DIALECT_RPG_III;
    }
    return DIALECT_RPG_IV;
}

/* The program object is named after the source member: the basename up to
 * its first dot, upper-cased (`custmnt.pgm.rpgle` -> CUSTMNT). A copybook is
 * not a program. */
static const char *program_name_for(CBMArena *a, const char *base) {
    if (path_has_ext(base, ".rpgleinc")) {
        return NULL;
    }
    const char *dot = strchr(base, '.');
    size_t n = dot ? (size_t)(dot - base) : strlen(base);
    if (n == 0) {
        return NULL;
    }
    return dup_upper(a, cbm_arena_strndup(a, base, n));
}

static uint32_t count_lines(const char *src, int len) {
    uint32_t n = 0;
    for (int i = 0; i < len; i++) {
        if (src[i] == '\n') {
            n++;
        }
    }
    if (len > 0 && src[len - SKIP_ONE] != '\n') {
        n++;
    }
    return n ? n : SKIP_ONE;
}

/* The program Function def. A cycle-main program spans its main-line
 * statements. A linear-main program (ctl-opt main(proc)) is entered through
 * that procedure, so the program def mirrors the procedure's range. */
static void emit_program(RpgState *s, uint32_t last_line) {
    if (!s->program_qn || s->nomain) {
        return;
    }
    if (s->linear_main) {
        s->program.start_line = SKIP_ONE;
        s->program.end_line = last_line;
        for (int i = 0; i < s->result->defs.count; i++) {
            const CBMDefinition *d = &s->result->defs.items[i];
            if (strcmp(d->label, "Function") == 0 && ieq(d->name, s->linear_main)) {
                s->program.start_line = d->start_line;
                s->program.end_line = d->end_line;
                break;
            }
        }
    } else if (!s->saw_main_statement) {
        return;
    }
    emit_function(s, &s->program, s->program.end_line, true);
}

void cbm_extract_rpg(CBMExtractCtx *ctx) {
    RpgState st;
    memset(&st, 0, sizeof(st));
    st.a = ctx->arena;
    st.result = ctx->result;
    st.rel_path = ctx->rel_path ? ctx->rel_path : "";
    st.module_qn = ctx->module_qn ? ctx->module_qn : "";
    const char *base = path_basename(st.rel_path);
    st.dialect = dialect_for(base);
    const char *program_name = program_name_for(st.a, base);
    if (program_name) {
        st.program_qn = cbm_arena_sprintf(st.a, "%s.%s", st.module_qn, program_name);
    }
    st.program.name = program_name;
    st.program.qn = st.program_qn;
    metrics_init(&st.program.metrics);

    const char *src = ctx->source;
    int len = ctx->source_len;
    uint32_t total = count_lines(src, len);

    CBMDefinition mod = def_base(&st, st.rel_path, st.module_qn, "Module", SKIP_ONE, total);
    mod.is_exported = true;
    mod.is_test = st.result->is_test_file;
    cbm_defs_push(&st.result->defs, st.a, mod);

    int pos = 0;
    uint32_t line = 0;
    while (pos < len && !st.stop) {
        int start = pos;
        while (pos < len && src[pos] != '\n') {
            pos++;
        }
        int llen = pos - start;
        if (llen > 0 && src[start + llen - SKIP_ONE] == '\r') {
            llen--;
        }
        pos++;
        line++;
        if (line == SKIP_ONE && is_free_marker(src + start, llen)) {
            st.fully_free = true;
            continue;
        }
        if (st.fully_free) {
            free_feed(&st, src + start, llen, line);
        } else {
            fixed_line(&st, src + start, llen, line);
        }
    }

    pending_flush(&st);
    stmt_finish(&st); /* a last statement missing its `;` */
    decl_end(&st);
    subr_end(&st, total);
    proc_end(&st, total);
    emit_program(&st, total);
    resolve_calls(&st);
}
