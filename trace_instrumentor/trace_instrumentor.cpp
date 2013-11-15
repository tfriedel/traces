/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
          2013 Thomas Friedel <thomas.friedel (_!at!_) gmaildotcom>
   Sponsored by infinidat (http://infinidat.com)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
***/

#include "trace_user.h"
#include <stdio.h>
#include <stdlib.h>

#include "clang/Rewrite/ASTConsumers.h"
#include "clang/Rewrite/Rewriter.h"
#include "clang/Lex/Lexer.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/DeclVisitor.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/AST/AST.h"
#include "clang/Frontend/CompilerInstance.h"
#include "llvm/Support/raw_ostream.h"
#include "TraceCall.h"
#include "trace_defs.h"
#include "trace_lib.h"

#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include <string>
#include <set>


#define TRACING_ENABLED std::string("true")


#define TRACE_FUNC_ENTRY(funcName, lineNo, logText, ...)                                                     \
    std::string("static int traceCounter_line_") + numberToStr(lineNo)                                       \
        + " = 0;\n bool entry_was_logged=false;\n" + "tracer::trace_log_func_entry(\"" + cpp_filename        \
        + "\", \"" + funcName + "\" ,\"" + logText + "\", &entry_was_logged, "  \
        + "&traceCounter_line_" + numberToStr(lineNo) + ", defaultMaxLogCallsPerFunction, " + __VA_ARGS__    \
        + ");\n"


#define TRACE_FUNC_EXIT(funcName, lineNo, logText, ...)                                                      \
    "tracer::trace_log_func_exit(\"" + cpp_filename + "\", \"" + funcName + "\" ,\"" + logText      \
       + "\", &entry_was_logged"  \
        + ", defaultMaxLogCallsPerFunction, " + __VA_ARGS__ + ");\n"

using namespace clang;

namespace
{
// static bool printFlags = true;
static bool printFlags = false;
static std::string cpp_filename = "";

static const Type *get_expr_type(const Expr *expr)
{
    return expr->getType().getCanonicalType().split().Ty;
}

static inline std::string numberToStr(int Number)
{
    return static_cast<std::ostringstream *>(&(std::ostringstream() << Number))->str();
}

std::string castTo(LangOptions const &langOpts, std::string orig_expr, std::string cast_type)
{
    if (langOpts.CPlusPlus == 1) {
        return "reinterpret_cast<" + cast_type + ">(" + orig_expr + ")";
    } else {
        return "(" + cast_type + ") (" + orig_expr + ")";
    }
}

std::string &replaceAll(std::string &result, const std::string &replaceWhat,
                        const std::string &replaceWithWhat)
{
    while (1) {
        const int pos = result.find(replaceWhat);
        if (pos == -1)
            break;
        result.replace(pos, replaceWhat.size(), replaceWithWhat);
    }
    return result;
}

/** converts string s to an escaped string where all special chars like ", \t
 *  are escaped */
static std::string escapeString(std::string const &s)
{
    std::stringstream b;
    // b << "\"";
    for (std::string::const_iterator i = s.begin(), end = s.end(); i != end; ++i) {
        unsigned char c = *i;
        if (' ' <= c and c <= '~' and c != '\\' and c != '"') {
            b << c;
        } else {
            b << "\\";
            switch (c) {
            case '"':
                b << "\"";
                break;
            case '\\':
                b << "\\";
                break;
            case '\t':
                b << "t";
                break;
            case '\r':
                b << "r";
                break;
            case '\n':
                b << "n";
                break;
            default:
                char const *const hexdig = "0123456789ABCDEF";
                b << "x";
                b << hexdig[c >> 4];
                b << hexdig[c & 0xF];
            }
        }
    }
    // b << "\"";
    return b.str();
}

static std::string printAisB(const std::string &a, const std::string &b)
{
    std::stringstream serialized;
    if (b.length() > 0) {
        serialized << "\"" << escapeString(a) << ": \""
                   << " << (" << b << ")";
    }
    return serialized.str();
}

static std::string printfAisB(const std::string &param_name, const std::string &expr_param,
                              const std::string &format_str)
{
    std::stringstream serialized;
    assert(format_str.length() > 0);
    serialized << param_name << ": " << format_str;
    return serialized.str();
}

static std::string normalizeTypeName(std::string type_str)
{
    std::string replaced = replaceAll(type_str, " ", "_");
    return replaceAll(replaced, ":", "_");
}

static std::string getString(const SourceLocation &loc, const SourceManager *SM)
{
    std::string S2;
    llvm::raw_string_ostream OS(S2);
    loc.print(OS, *SM);
    return OS.str();
}

// Pair of start, end positions in the source.
typedef std::pair<unsigned, unsigned> SrcRange;

// Get the the location of the next semicolon following a statement
SourceLocation getNextSemicolon(const clang::Stmt *S, const clang::SourceManager *SM)
{
    clang::SourceLocation SLoc = SM->getExpansionLoc(S->getLocStart());
    SourceLocation loc = SLoc;

    // keep looking for ';' by advancing one character at a time until we find it

    enum { /*Enum construct declares states */
           DOUBLEQUOTE,
           SINGLEQUOTE,
           BACKSLASH,
           BACKSLASH_SINGLEQUOTE,
           BACKSLASH_DOUBLEQUOTE,
           LITERAL,
           SEMICOLON } state;

    state = LITERAL;
    char c;
    while (state != SEMICOLON) {
        c = *SM->getCharacterData(loc);
        switch (state) {
        case LITERAL:
            switch (c) {
            case ';':
                state = SEMICOLON;
                break;
            case '"':
                state = DOUBLEQUOTE;
                break;
            case '\'':
                state = SINGLEQUOTE;
                break;
            case '\\':
                state = BACKSLASH;
                break;
            default:
                break;
            }
            break;
        case SINGLEQUOTE:
            switch (c) {
            case '\'':
                state = LITERAL;
                break;
            case '\\':
                state = BACKSLASH_SINGLEQUOTE;
                break;
            default:
                break;
            }
            break;
        case DOUBLEQUOTE:
            switch (c) {
            case '"':
                state = LITERAL;
                break;
            case '\\':
                state = BACKSLASH_DOUBLEQUOTE;
                break;
            default:
                break;
            }
            break;
        case BACKSLASH:
            state = LITERAL;
            break;
        case BACKSLASH_SINGLEQUOTE:
            state = SINGLEQUOTE;
            break;
        case BACKSLASH_DOUBLEQUOTE:
            state = DOUBLEQUOTE;
            break;
        case SEMICOLON:
            switch (c) {
            case ';':
                state = SEMICOLON;
                break;
            case '"':
                state = DOUBLEQUOTE;
                break;
            case '\'':
                state = SINGLEQUOTE;
                break;
            case '\\':
                state = BACKSLASH;
                break;
            default:
                break;
            }
        }
        if (state != SEMICOLON) {
            loc = loc.getLocWithOffset(1);
        }
    }
    return loc;
}

static std::string getLiteralExpr(ASTContext &ast, Rewriter *Rewrite, const clang::Stmt *S)
{
    SourceManager *SM = &ast.getSourceManager();
    clang::SourceLocation SLoc = SM->getExpansionLoc(S->getLocStart());
    const char *startBuf = SM->getCharacterData(SLoc);
    const char *endBuf = SM->getCharacterData(getNextSemicolon(S, SM));
    std::string retString(startBuf, endBuf - startBuf);
    return retString;
}

void hasReturnStmts(Stmt *S, bool &hasReturns)
{
    for (Stmt::child_range CI = S->children(); CI; ++CI)
        if (*CI)
            hasReturnStmts(*CI, hasReturns);

    if (isa<ReturnStmt>(S))
        hasReturns = true;
    return;
}

static SourceLocation getReturnStmtEnd(ASTContext &ast, Rewriter *Rewrite, ReturnStmt *S)
{
    SourceManager *SM = &ast.getSourceManager();
    SourceLocation semiLoc = getNextSemicolon(S, SM).getLocWithOffset(1);
    return semiLoc;
}

bool TraceParam::parseCStrTypeParam(QualType qual_type)
{
    type = qual_type.split().Ty;
    if (type->isPointerType()) {
        const Type *pointeeType = type->getPointeeType().split().Ty;
        if (!(pointeeType->isBuiltinType())) {
            return false;
        } else {
            const BuiltinType *BT = pointeeType->getAs<BuiltinType>();
            if (BT->isCharType()) {
                flags |= TRACE_PARAM_FLAG_CSTR;
                size = ast.getTypeSize(type) / 8;
                type_name = QualType(qual_type.split().Ty, 0).getAsString();
                is_pointer = true;
                return true;
            } else {
                return false;
            }
        }
    }
    return false;
}

bool TraceParam::parseBasicTypeParam(QualType qual_type)
{
    type = qual_type.split().Ty;

    if (type->isReferenceType() || type->isPointerType()) {
        size = ast.getTypeSize(type);
        type_name = qual_type.getAsString();

        if (type->isReferenceType()) {
            is_reference = true;
        } else {
            is_pointer = true;
        }

        flags = TRACE_PARAM_FLAG_HEX;
        if (size == 64) {
            flags |= TRACE_PARAM_FLAG_NUM_64;
        } else {
            flags |= TRACE_PARAM_FLAG_NUM_32;
        }

        size = ast.getTypeSize(type) / 8;
        return true;
    }

    if (!type->isBuiltinType()) {
        return false;
    }

    switch (ast.getTypeSize(type)) {
    case 8:
        flags |= TRACE_PARAM_FLAG_NUM_8;
        break;
    case 16:
        flags |= TRACE_PARAM_FLAG_NUM_16;
        break;
    case 32:
        flags |= TRACE_PARAM_FLAG_NUM_32;
        break;
    case 64:
        flags |= TRACE_PARAM_FLAG_NUM_64;
        break;
    default:
        return false;
    }

    const BuiltinType *BT = qual_type->getAs<BuiltinType>();
    // if (BT->getKind() == BuiltinType::Double) {
    if (BT->isFloatingPoint()) {
        size = ast.getTypeSize(type) / 8;
        type_name = QualType(qual_type.split().Ty, 0).getAsString();
        flags |= TRACE_PARAM_FLAG_FP;
        return true;
    }

    if (!type->isIntegerType()) {
        return false;
    }

    if (!type->isSignedIntegerType()) {
        flags |= TRACE_PARAM_FLAG_UNSIGNED;
    }

    size = ast.getTypeSize(type) / 8;
    type_name = QualType(qual_type.split().Ty, 0).getAsString();
    if (type_name.compare("_Bool") == 0) {
        type_name = "bool";
    }

    return true;
}

bool TraceParam::parseBasicTypeParam(const Expr *expr)
{
    const Expr *stripped_expr = expr->IgnoreImpCasts();

    const Type *type = get_expr_type(stripped_expr);
    if (NULL == type) {
        std::cout << "couldn't get type from basic expression." << std::endl;
        return false;
    }

    bool parsed = parseBasicTypeParam(expr->getType().getCanonicalType());
    if (!parsed) {
        std::cout << "parseBasicTypeParam() not successful." << std::endl;
        return false;
    }

    expression = getLiteralExpr(ast, Rewrite, expr);
    std::cout << "expression = " << expression << std::endl;
    return true;
}

bool TraceParam::parseRecordTypeParam(const Expr *expr)
{
    const Expr *stripped_expr = expr->IgnoreImpCasts();

    const Type *type = get_expr_type(stripped_expr);
    if (NULL == type) {
        return false;
    }

    if (!type->isRecordType()) {
        return false;
    }

    //    referenceType(type);
    flags |= TRACE_PARAM_FLAG_RECORD;
    expression = getLiteralExpr(ast, Rewrite, expr);
    type_name = expr->getType().getCanonicalType().getAsString();
    return true;
}

bool TraceParam::parseEnumTypeParam(QualType qual_type)
{
    if (!qual_type.split().Ty->isEnumeralType()) {
        return false;
    }

    const EnumType *enum_type = qual_type->getAs<EnumType>();
    if (!enum_type->getDecl()->getIdentifier()) {
        return false;
    }

    //    referenceType(qual_type.split().Ty);
    flags |= TRACE_PARAM_FLAG_ENUM;
    type_name = qual_type.getAsString();
    size = 4;
    return true;
}

bool TraceParam::parseEnumTypeParam(const Expr *expr)
{
    // Enum's are implicitly cast to ints.
    const Expr *stripped_expr = expr->IgnoreImpCasts();

    const Type *type = get_expr_type(stripped_expr);
    if (NULL == type) {
        return false;
    }

    if (!parseEnumTypeParam(stripped_expr->getType().getCanonicalType().getUnqualifiedType())) {
        return false;
    }

    expression = getLiteralExpr(ast, Rewrite, expr);

    return true;
}

void TraceCall::replaceExpr(const Expr *expr, std::string replacement)
{
    SourceRange source_range = expr->getSourceRange();
    unsigned int size = Rewrite->getRangeSize(source_range);

    Rewrite->ReplaceText(expr->getLocStart(), size, replacement);
}

std::string TraceCall::genMIN(std::string &a, std::string &b)
{
    std::stringstream code;
    code << "((" << a << ")<(" << b << ") ? (" << a << "):(" << b << "))";
    return code.str();
}

std::string TraceCall::constlength_writeSimpleValue(std::string &expression, std::string &type_name,
                                                    bool is_pointer, bool is_reference,
                                                    unsigned int value_size, const Type *type)
{
    std::stringstream serialized;
    if (!is_reference && !is_pointer) {
        std::stringstream new_expression;
        if (type->isFloatingType()) {
            new_expression << "(tracer::float_to_hex(" << expression << "))";
        } else if (type->isCharType()) {
            if (type->isSignedIntegerType()) {
                new_expression << "(static_cast<int>(" << expression << ") & 0xFFFF)";
            } else {
                new_expression << "(static_cast<unsigned int>(" << expression << ") & 0xFFFF)";
            }
        } else {
            new_expression << "(" << expression << ")";
        }
        serialized << printAisB(expression, new_expression.str());
    } else if (is_reference || is_pointer) {
        serialized << "\"" << escapeString(expression) << ": \""
                   << " << (";

        if (type) {
            bool unhandledType = false;
            bool floatingPointType = false;
            bool integerType = false;
            if (!(type->isReferenceType() || type->isPointerType())) {
                serialized << "\"[!isPointerType()]\"";
                unhandledType = true;
            } else {
                const Type *pointeeType = type->getPointeeType().split().Ty;
                if (!(pointeeType->isBuiltinType())) {
                    serialized << "\"[!(pointeeType->isBuiltinType())]\"";
                    unhandledType = true;
                } else {
                    const BuiltinType *BT = pointeeType->getAs<BuiltinType>();
                    // if (BT->getKind() == BuiltinType::Double) {
                    if (BT->isFloatingPoint()) {
                        int size = ast.getTypeSize(type) / 8;
                        std::string type_name = QualType(pointeeType, 0).getAsString();
                        floatingPointType = true;
                    } else if (pointeeType->isIntegerType()) {
                        integerType = true;
                    } else {
                        unhandledType = true;
                    }
                }
            }
            if (unhandledType) {
                serialized << "\"[unhandledType: " + type_name + "]\"";
            } else if (integerType || floatingPointType) {
                serialized << "(";
                std::stringstream new_expression;
                if (is_pointer) {
                    new_expression << "*";
                }
                new_expression << expression;
                if (floatingPointType) {
                    serialized << "tracer::float_to_hex(" << new_expression.str() << "))";
                } else {
                    serialized << new_expression.str() << ")";
                }
            }
        }

        serialized << ")";
    }
    //@todo handle pointers, references etc
    return serialized.str();
}

bool TraceParam::calcSimpleValueRepr()
{
    std::stringstream expr_param_stream;
    if (!is_reference && !is_pointer) {
        if (type->isFloatingType()) {
            format_str = "%a";
        } else if (type->isCharType()) {
            if (type->isSignedIntegerType()) {
                format_str = "%d";
            } else {
                format_str = "%u";
            }
        } else {
            if (type->isSignedIntegerType()) {
                format_str = "%d";
            } else if (type->isUnsignedIntegerType()) {
                format_str = "%u";
            } else {
                format_str = "%s";
                expr_param = "\"unhandled basic type\"";
            }
        }
        if (expr_param == "") {
            expr_param = expression;
        }

    } else if (is_reference || is_pointer) {
        if (type) {
            bool unhandledType = false;
            bool floatingPointType = false;
            bool integerType = false;
            if (!(type->isReferenceType() || type->isPointerType())) {
                format_str = "%s";
                expr_param_stream << "\"[!isPointerType()]\"";
                unhandledType = true;
            } else {
                const Type *pointeeType = type->getPointeeType().split().Ty;
                if (!(pointeeType->isBuiltinType())) {
                    format_str = "%s";
                    expr_param_stream << "\"[!(pointeeType->isBuiltinType())]\"";
                    unhandledType = true;
                } else {
                    const BuiltinType *BT = pointeeType->getAs<BuiltinType>();
                    // if (BT->getKind() == BuiltinType::Double) {
                    if (BT->isFloatingPoint()) {
                        int size = ast.getTypeSize(type) / 8;
                        std::string type_name = QualType(pointeeType, 0).getAsString();
                        floatingPointType = true;
                        format_str = "%a";
                    } else if (pointeeType->isSignedIntegerType()) {
                        integerType = true;
                        format_str = "%d";
                    } else if (pointeeType->isUnsignedIntegerType()) {
                        integerType = true;
                        format_str = "%u";
                    } else {
                        unhandledType = true;
                    }
                }
            }
            if (unhandledType) {
                expr_param_stream << "\"[unhandledType :" + type_name + "]\"";
                format_str = "%s";
            } else if (integerType || floatingPointType) {
                expr_param_stream << "(";
                std::stringstream new_expression;
                if (is_pointer) {
                    new_expression << "*";
                }
                new_expression << expression;
                expr_param_stream << new_expression.str() << ")";
            }
        }
        expr_param = expr_param_stream.str();
    }
    std::cout << "calcSimpleValueRepr: "
              << "expr_param: " << expr_param << " format_str: " << format_str
              << " expression: " << expression << std::endl;
    return true;
}

std::string TraceCall::getExpansion()
{
    std::stringstream start_record;
    std::vector<std::string> parameters;
    for (unsigned int i = 0; i < args.size(); i++) {
        TraceParam &param = args[i];
        std::cout << param.asString() << std::endl;
        std::string paramStr;
        if ((param.flags & TRACE_PARAM_FLAG_CSTR)) {
            param.expr_param = param.expression;
            if (param.expression != "") {
                param.format_str = "%s";
            } else {
                param.format_str = "";
            }
            paramStr = printfAisB(param.expression, param.expr_param, param.format_str);

        } else if (param.isSimple() || param.isVarString()) {
            param.calcSimpleValueRepr();
            paramStr = printfAisB(param.param_name, param.expr_param, param.format_str);

        } else if (param.isBuffer()) {
            assert(false);
            /*
            start_record.str("");
            start_record << " << \"" << param.expression << ": \""
                         << "[buffer]";
            parameters.push_back(start_record.str());
            */
            // @todo implement buffer output correctly
        }
        if (param.format_str != "") {
            parameters.push_back(paramStr);
        }
    }
    // clear
    start_record.str("");
    int i = 0;
    bool empty = true;
    for (std::vector<std::string>::iterator it = parameters.begin(); it != parameters.end(); ++it, ++i) {

        start_record << *it;
        empty = false;
        if (i < parameters.size() - 1) {
            start_record << ", ";
        }
    }
    if (empty) {
        start_record << "\"\"";
    }
    std::cout << "traceCall:getExpansion() = " << start_record.str() << std::endl;
    return start_record.str();
}

std::string TraceCall::getParameterListStr()
{
    std::stringstream start_record;
    std::vector<std::string> parameters;
    for (unsigned int i = 0; i < args.size(); i++) {
        TraceParam &param = args[i];
        if (param.format_str != "") {
            parameters.push_back(param.expr_param);
        }
    }
    // clear
    start_record.str("");
    int i = 0;
    bool empty = true;
    for (std::vector<std::string>::iterator it = parameters.begin(); it != parameters.end(); ++it, ++i) {
        start_record << *it;
        empty = false;
        if (i < parameters.size() - 1) {
            start_record << ", ";
        }
    }
    if (empty) {
        start_record << "0";
    }
    std::cout << "traceCall:getParameterListStr() = '" << start_record.str() << "'" << std::endl;
    return start_record.str();
}

class FunctionCallerFinder : public StmtVisitor<FunctionCallerFinder>
{
    unsigned int call_count;
    CallExpr *CE;
    std::string function_name;

public:
    void VisitCallExpr(CallExpr *_CE)
    {
        const FunctionDecl *callee = _CE->getDirectCallee();
        if (function_name.compare(callee->getNameAsString()) == 0) {
            call_count++;
            CE = _CE;
        }
    }

    void VisitStmt(Stmt *stmt)
    {
        Stmt::child_iterator CI, CE = stmt->child_end();
        for (CI = stmt->child_begin(); CI != CE; ++CI) {
            if (*CI != 0) {
                Visit(*CI);
            }
        }
    }

    CallExpr *functionHasFunctionCall(Stmt *body, std::string _function_name, int *_call_count)
    {
        function_name = _function_name;
        CE = NULL;
        call_count = 0;
        Visit(body);
        *_call_count = call_count;
        return CE;
    }
};

class StructFinder : public DeclVisitor<StructFinder>
{
    RecordDecl *RD;
    std::string decl_name;

public:
    void VisitRecordDecl(RecordDecl *_RD)
    {
        if (_RD->isCompleteDefinition()) {
            VisitDeclContext(_RD);
            if (_RD->getDeclName().getAsString().compare(decl_name) == 0) {
                RD = _RD;
            }
        }
    }

    void VisitLinkageSpecDecl(LinkageSpecDecl *D)
    {
        if (D->hasBraces()) {
            VisitDeclContext(D);
        } else {
            Visit(*D->decls_begin());
        }
    }

    void VisitNamespaceDecl(NamespaceDecl *D)
    {
        VisitDeclContext(D);
    }

    void VisitCXXRecordDecl(CXXRecordDecl *_RD)
    {
        if (_RD->isCompleteDefinition()) {
            VisitDeclContext(_RD);
            if (_RD->getDeclName().getAsString().compare(decl_name) == 0) {
                RD = dyn_cast<RecordDecl>(_RD);
            }
        }
    }

    void VisitEnumDecl(EnumDecl *D)
    {
        if (D->isCompleteDefinition()) {
            VisitDeclContext(D);
        }
    }

    void VisitDeclContext(DeclContext *DC)
    {
        for (DeclContext::decl_iterator D = DC->decls_begin(), DEnd = DC->decls_end(); D != DEnd; ++D) {
            Visit(*D);
        }
    }

    void VisitTranslationUnitDecl(TranslationUnitDecl *D)
    {
        VisitDeclContext(D);
    }

    RecordDecl *findDeclByName(Decl *body, std::string _decl_name)
    {
        decl_name = _decl_name;
        RD = NULL;
        Visit(body);
        return RD;
    }
};

bool TraceParam::parseClassTypeParam(const Expr *expr)
{
    const Type *type = expr->getType().getTypePtr();

    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().split().Ty;
    if (!pointeeType->isClassType()) {
        return false;
    }

    CXXRecordDecl *RD = cast<CXXRecordDecl>(pointeeType->getAs<RecordType>()->getDecl());
    CXXMethodDecl *MD = NULL;
    for (CXXRecordDecl::method_iterator method = RD->method_begin(); method != RD->method_end(); ++method) {
        if (method->getNameAsString().compare("_trace_represent") == 0) {
            if (!method->hasInlineBody()) {
                Diags.Report(ast.getFullLoc(method->getLocStart()), NonInlineTraceRepresentDiag)
                    << method->getSourceRange();
                return false;
            }

            MD = *method;
            break;
        }
    }

    if (NULL == MD) {
        return false;
    }

    FunctionCallerFinder finder;
    int call_count;
    CallExpr *call_expr = finder.functionHasFunctionCall(MD->getBody(), "REPR", &call_count);
    if (call_expr == NULL) {
        return false;
    }

    if (call_count > 1) {
        Diags.Report(ast.getFullLoc(call_expr->getLocStart()), MultipleReprCallsDiag)
            << call_expr->getSourceRange();
    }

    return false;
    //    TraceCall *_trace_call = new TraceCall(Out, Diags, ast, Rewrite);
    //    if (!_trace_call->fromCallExpr(call_expr)) {
    //        return false;
    //    }

    //    trace_call = _trace_call;
    //    // TODO: Unique name, don't add duplicate logs
    //    std::string _type_name
    //        = normalizeTypeName(QualType(pointeeType, 0).getAsString());
    //    std::stringstream trace_call_name;
    //    trace_call_name << _type_name;
    //    trace_call_name << "_tracelog";
    //    trace_call->trace_call_name = trace_call_name.str();
    //    method_generated = true;
    //    flags |= TRACE_PARAM_FLAG_NESTED_LOG;
    //    expression = "(" + getLiteralExpr(ast, Rewrite, expr)
    //                 + ")->_trace_represent";
    //    type_name = QualType(pointeeType, 0).getAsString();

    //    return true;
}

bool TraceParam::parseHexBufParam(const Expr *expr)
{
    const Expr *stripped_expr = expr->IgnoreParens();
    if (!isa<CStyleCastExpr>(stripped_expr)) {
        return false;
    }

    const Type *type = stripped_expr->getType().getTypePtr();
    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().IgnoreParens().getTypePtr();
    if (pointeeType->getTypeClass() != Type::VariableArray && pointeeType->getTypeClass()
                                                              != Type::ConstantArray) {
        return false;
    }

    const ArrayType *A = dyn_cast<ArrayType>(pointeeType);
    if (A->getElementType().split().Ty->getTypeClass() != Type::Typedef) {
        return false;
    }

    const TypedefType *TDP = dyn_cast<TypedefType>(A->getElementType().split().Ty);
    const TypedefNameDecl *decl = TDP->getDecl();
    if (decl->getDeclName().getAsString().compare("hex_t") != 0) {
        return false;
    }

    flags |= TRACE_PARAM_FLAG_UNSIGNED | TRACE_PARAM_FLAG_VARRAY | TRACE_PARAM_FLAG_NUM_8
             | TRACE_PARAM_FLAG_HEX;

    if (isa<VariableArrayType>(A)) {
        const VariableArrayType *VAT = dyn_cast<VariableArrayType>(A);
        size_expression = getLiteralExpr(ast, Rewrite, VAT->getSizeExpr());
    } else if (isa<ConstantArrayType>(A)) {
        const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(A);
        size = CAT->getSize().getZExtValue();
    }

    expression = getLiteralExpr(ast, Rewrite, expr);
    return true;
}

std::string TraceParam::getLiteralString(const Expr *expr)
{
    std::string empty_string;
    if (!isa<StringLiteral>(expr)) {
        return empty_string;
    }

    const StringLiteral *string_literal = dyn_cast<StringLiteral>(expr);
    return string_literal->getString();
}

bool TraceParam::parseStringParam(QualType qual_type)
{
    const Type *type = qual_type.split().Ty;
    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().split().Ty;
    if (!(pointeeType->isBuiltinType() && pointeeType->isCharType())) {
        return false;
    }

    type_name = qual_type.getAsString();
    return true;
}

bool TraceParam::parseStringParam(const Expr *expr)
{
    const Type *type = get_expr_type(expr);
    if (NULL == type) {
        return false;
    }
    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().split().Ty;
    if (!(pointeeType->isBuiltinType() && pointeeType->isCharType())) {
        return false;
    }

    const Expr *stripped_expr = expr->IgnoreImpCasts();
    if (isa<StringLiteral>(stripped_expr)) {
        std::string literalString = getLiteralString(stripped_expr);
        if (literalString.length() != 0) {
            type_name = expr->getType().getCanonicalType().getAsString();
            const_str = literalString;
            return true;
        } else {
            Diags.Report(ast.getFullLoc(stripped_expr->getLocStart()), EmptyLiteralStringDiag)
                << stripped_expr->getSourceRange();
            return false;
        }
    }

    std::string stringExpression = getLiteralExpr(ast, Rewrite, expr);
    if (stringExpression.length() != 0) {
        expression = stringExpression;
        flags |= TRACE_PARAM_FLAG_STR | TRACE_PARAM_FLAG_VARRAY;
        type_name = expr->getType().getCanonicalType().getAsString();
        return true;
    }

    return false;
}

void TraceCall::unknownTraceParam(const Expr *trace_param)
{
    Diags.Report(ast.getFullLoc(trace_param->getLocStart()), UnknownTraceParamDiag)
        << trace_param->getSourceRange();
}

static std::string getCallExprFunctionName(const CallExpr *CE)
{
    const FunctionDecl *callee = CE->getDirectCallee();
    if (NULL == callee) {
        return std::string();
    }

    return callee->getQualifiedNameAsString();
}

bool TraceParam::fromType(QualType type, bool fill_unknown_type)
{
    QualType canonical_type = type.getCanonicalType();
    if (parseCStrTypeParam(canonical_type)) {
        return true;
    } else if (parseEnumTypeParam(canonical_type)) {
        return true;
    } else if (parseBasicTypeParam(canonical_type)) {
        return true;
    }

    if (fill_unknown_type) {
        const_str = "...";
        return true;
    } else {
        return false;
    }
}

bool TraceParam::fromExpr(const Expr *trace_param, bool deref_pointer)
{
    std::cout << "--> fromExpr()" << std::endl;
    if (deref_pointer && parseStringParam(trace_param)) {
        return true;
    } else if (parseHexBufParam(trace_param)) {
        return true;
    } else if (parseEnumTypeParam(trace_param)) {
        return true;
    } else if (deref_pointer && parseRecordTypeParam(trace_param)) {
        return true;
    } else if (deref_pointer && parseClassTypeParam(trace_param)) {
        return true;
    } else if (parseBasicTypeParam(trace_param)) {
        std::cout << "TraceParam::fromExpr() = true (parseBasicTypeParam)" << std::endl;
        return true;
    }
    std::cout << "TraceParam::fromExpr() = false" << std::endl;
    return false;
}

static bool valid_param_name(std::string &name)
{
    const char *ptr = name.c_str();
    if (isdigit(*ptr) || ispunct(*ptr)) {
        return false;
    }

    while (*ptr) {
        char c = *ptr;
        if (!isalnum(c) && c != '_') {
            return false;
        }
        ptr++;
    }

    return true;
}

bool TraceCall::constantSizeTrace(void)
{
    for (unsigned int i = 0; i < args.size(); i++) {
        TraceParam &param = args[i];
        if (param.isVarString() || param.isBuffer() || param.trace_call) {
            return false;
        }

        if (param.trace_call) {
            return false;
        }
    }

    return true;
}

static bool shouldInstrumentFunctionDecl(const FunctionDecl *D, bool whitelistExceptions)
{
    //@todo: implement filters
    if (D->isInlined()) {
        return false;
        if (!(D->isCXXClassMember() || D->isCXXInstanceMember())) {
            return false;
        }
        if (D->isTrivial() || D->isHidden() || D->isRecord() || D->hasTrivialBody()) {
            return false;
        }
        // @todo: is this function defined in namespace std
    }

    if (whitelistExceptions) {
        if (D->hasAttr<NoInstrumentFunctionAttr>()) {
            return true;
        } else {
            return false;
        }
    } else {
        if (D->hasAttr<NoInstrumentFunctionAttr>()) {
            return false;
        } else {
            return true;
        }
    }
}

static SourceLocation getFunctionBodyStart(Stmt *FB)
{
    SourceLocation startLoc;
    startLoc = FB->getLocStart();

    return startLoc.getLocWithOffset(1);
}

class DeclIterator : public DeclVisitor<DeclIterator>
{
public:
    llvm::raw_ostream &Out;
    DiagnosticsEngine &Diags;
    ASTContext &ast;
    Rewriter *Rewrite;
    SourceManager *SM;
    LangOptions langOpts;
    bool whitelistExceptions;

    DeclIterator(llvm::raw_ostream &xOut, DiagnosticsEngine &_Diags, ASTContext &xAst, Rewriter *rewriter,
                 SourceManager *sm, const LangOptions &_langOpts)
        : Out(xOut), Diags(_Diags), ast(xAst), Rewrite(rewriter), SM(sm), langOpts(_langOpts),
          whitelistExceptions(false) {};
    void VisitDeclContext(DeclContext *DC, bool Indent = true);
    void VisitTranslationUnitDecl(TranslationUnitDecl *D);
    void VisitTypedefDecl(TypedefDecl *D);
    void VisitTypeAliasDecl(TypeAliasDecl *D);
    void VisitEnumDecl(EnumDecl *D);
    void VisitRecordDecl(RecordDecl *D);
    void VisitEnumConstantDecl(EnumConstantDecl *D);
    void VisitFunctionDecl(FunctionDecl *D);
    void VisitFieldDecl(FieldDecl *D);
    void VisitVarDecl(VarDecl *D);
    void VisitLabelDecl(LabelDecl *D);
    void VisitParmVarDecl(ParmVarDecl *D);
    void VisitFileScopeAsmDecl(FileScopeAsmDecl *D);
    void VisitStaticAssertDecl(StaticAssertDecl *D);
    void VisitNamespaceDecl(NamespaceDecl *D);
    void VisitUsingDirectiveDecl(UsingDirectiveDecl *D);
    void VisitNamespaceAliasDecl(NamespaceAliasDecl *D);
    void VisitCXXRecordDecl(CXXRecordDecl *D);
    void VisitLinkageSpecDecl(LinkageSpecDecl *D);
    void VisitTemplateDecl(const TemplateDecl *D);
    void VisitFunctionTemplateDecl(FunctionTemplateDecl *D);
    void VisitClassTemplateDecl(ClassTemplateDecl *D);
};

class StmtIterator : public StmtVisitor<StmtIterator>
{
public:
    llvm::raw_ostream &Out;
    DiagnosticsEngine &Diags;
    ASTContext &ast;
    Rewriter *Rewrite;
    SourceManager *SM;
    LangOptions langOpts;
    Decl *D;
    bool whitelistExceptions;

    StmtIterator(llvm::raw_ostream &xOut, DiagnosticsEngine &_Diags, ASTContext &xAst, Rewriter *rewriter,
                 SourceManager *sm, const LangOptions &_langOpts, Decl *_D, bool _whitelistExceptions)
        : Out(xOut), Diags(_Diags), ast(xAst), Rewrite(rewriter), SM(sm), langOpts(_langOpts), D(_D),
          whitelistExceptions(_whitelistExceptions) {};

#define STMT(Node, Base) void Visit##Node(Node *S);
#include <clang/AST/StmtNodes.inc>

    void VisitStmt(Stmt *S);
    void VisitDecl(Decl *D);
    void VisitType(QualType T);
    void VisitName(DeclarationName Name);
    void VisitNestedNameSpecifier(NestedNameSpecifier *NNS);
    void VisitTemplateName(TemplateName Name);
    void VisitTemplateArguments(const TemplateArgumentLoc *Args, unsigned NumArgs);
    void VisitTemplateArgument(const TemplateArgument &Arg);

private:
    void expandTraceLog(unsigned int severity, CallExpr *S);
};

void DeclIterator::VisitDeclContext(DeclContext *DC, bool Indent)
{
    for (DeclContext::decl_iterator D = DC->decls_begin(), DEnd = DC->decls_end(); D != DEnd; ++D) {
        Visit(*D);
    }
}

void DeclIterator::VisitTranslationUnitDecl(TranslationUnitDecl *D)
{
    VisitDeclContext(D, false);
}

void DeclIterator::VisitTypedefDecl(TypedefDecl *D)
{
}

void DeclIterator::VisitTypeAliasDecl(TypeAliasDecl *D)
{
}

void DeclIterator::VisitEnumDecl(EnumDecl *D)
{
    if (D->isCompleteDefinition()) {
        VisitDeclContext(D);
    }
}

void DeclIterator::VisitRecordDecl(RecordDecl *D)
{
    if (D->isCompleteDefinition()) {
        VisitDeclContext(D);
    }
}

void DeclIterator::VisitEnumConstantDecl(EnumConstantDecl *D)
{
}

void DeclIterator::VisitFunctionDecl(FunctionDecl *D)
{
    std::string expansion;
    std::string parameterlist;
    std::cout << "--> VisitFunctionDecl()" << std::endl;
    if (NULL != strstr(D->getQualifiedNameAsString().c_str(), "std::")) {
        return;
    }

    if (NULL != strstr(D->getQualifiedNameAsString().c_str(), "tracer::")) {
        return;
    }
    if (isa<CXXMethodDecl>(D)) {
        CXXMethodDecl *method_decl = dyn_cast<CXXMethodDecl>(D);
        CXXRecordDecl *class_decl = method_decl->getParent();
        if (class_decl->isDependentType()) {
            return;
        }
    }

    if (!(D->hasBody() && D->isThisDeclarationADefinition())) {
        return;
    }
    StmtIterator stmtiterator(Out, Diags, ast, Rewrite, SM, langOpts, D, whitelistExceptions);

    bool has_returns = false;
    Stmt *stmt = D->getBody();
    SourceLocation function_start = getFunctionBodyStart(stmt);
    TraceParam trace_param(Out, Diags, ast, Rewrite);
    TraceParam function_name_param(Out, Diags, ast, Rewrite);
    function_name_param.setConstStr(D->getQualifiedNameAsString());
    TraceCall trace_call(Out, Diags, ast, Rewrite);
    //    trace_call.addTraceParam(function_name_param);
    enum trace_severity severity = TRACE_SEV_FUNC_TRACE;

    if (NULL != strstr(D->getQualifiedNameAsString().c_str(), "_trace_represent")) {
        goto exit;
    }

    trace_call.setSeverity(severity);
    trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY");
    if (!shouldInstrumentFunctionDecl(D, whitelistExceptions)) {
        goto exit;
    }
    hasReturnStmts(stmt, has_returns);
    if (!has_returns || D->getResultType()->isVoidType()) {
        SourceLocation endLocation = stmt->getLocEnd();
        TraceParam trace_param(Out, Diags, ast, Rewrite);
        TraceParam function_name_param(Out, Diags, ast, Rewrite);

        function_name_param.setConstStr(D->getQualifiedNameAsString());

        TraceCall trace_call(Out, Diags, ast, Rewrite);
        enum trace_severity severity = TRACE_SEV_FUNC_TRACE;
        trace_call.setSeverity(severity);
        trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE");
        trace_call.addTraceParam(function_name_param);
        // replace }
        expansion = trace_call.getExpansion();
        parameterlist = trace_call.getParameterListStr();
        Rewrite->ReplaceText(endLocation, 1, TRACE_FUNC_EXIT(function_name_param.const_str,
                                                             SM->getPresumedLineNumber(function_start),
                                                             expansion, parameterlist) + std::string("}"));
    }

    // handle function parameters
    for (FunctionDecl::param_const_iterator I = D->param_begin(), E = D->param_end(); I != E; ++I) {
        trace_param.clear();
        if ((*I)->getNameAsString().length() == 0) {
            continue;
        }
        bool was_parsed = trace_param.fromType((*I)->getType().getCanonicalType(), true);
        if (!was_parsed) {
            stmtiterator.Visit(D->getBody());
            return;
        }

        trace_param.param_name = (*I)->getNameAsString();
        trace_param.expression = (*I)->getNameAsString();
        trace_call.addTraceParam(trace_param);
    }
    expansion = trace_call.getExpansion();
    parameterlist = trace_call.getParameterListStr();
    Rewrite->InsertText(
        function_start,
        TRACE_FUNC_ENTRY(function_name_param.const_str, SM->getPresumedLineNumber(function_start),
                         trace_call.getExpansion(), trace_call.getParameterListStr()),
        true);
exit:
    stmtiterator.Visit(D->getBody());
}

void DeclIterator::VisitFieldDecl(FieldDecl *D)
{
}

void DeclIterator::VisitLabelDecl(LabelDecl *D)
{
}

void DeclIterator::VisitVarDecl(VarDecl *D)
{
    std::string varName = D->getNameAsString();
    if (varName.compare("__traces_file_no_instrument") == 0) {
        whitelistExceptions = true;
    }
}

void DeclIterator::VisitParmVarDecl(ParmVarDecl *D)
{
    VisitVarDecl(D);
}

void DeclIterator::VisitFileScopeAsmDecl(FileScopeAsmDecl *D)
{
}

void DeclIterator::VisitStaticAssertDecl(StaticAssertDecl *D)
{
}

//----------------------------------------------------------------------------
// C++ declarations
//----------------------------------------------------------------------------
void DeclIterator::VisitNamespaceDecl(NamespaceDecl *D)
{
    VisitDeclContext(D);
}

void DeclIterator::VisitUsingDirectiveDecl(UsingDirectiveDecl *D)
{
}

void DeclIterator::VisitNamespaceAliasDecl(NamespaceAliasDecl *D)
{
}

void DeclIterator::VisitCXXRecordDecl(CXXRecordDecl *D)
{
    VisitDeclContext(D);
}

void DeclIterator::VisitLinkageSpecDecl(LinkageSpecDecl *D)
{
    if (D->hasBraces()) {
        VisitDeclContext(D);
    } else
        Visit(*D->decls_begin());
}

void DeclIterator::VisitFunctionTemplateDecl(FunctionTemplateDecl *D)
{
    return;
    return;
    for (FunctionTemplateDecl::spec_iterator I = D->spec_begin(), E = D->spec_end(); I != E; ++I) {
        Visit(*I);
    }

    return VisitRedeclarableTemplateDecl(D);
}

void DeclIterator::VisitClassTemplateDecl(ClassTemplateDecl *D)
{
    return;
    for (ClassTemplateDecl::spec_iterator I = D->spec_begin(), E = D->spec_end(); I != E; ++I) {
        Visit(*I);
    }

    VisitRedeclarableTemplateDecl(D);
}

void DeclIterator::VisitTemplateDecl(const TemplateDecl *D)
{
    return;
    // if (const TemplateTemplateParmDecl *TTP =
    //     dyn_cast<TemplateTemplateParmDecl>(D)) {
    //     return;
    // } else {
    //   Visit(D->getTemplatedDecl());
    // }
}

static SourceRange getDeclRange(SourceManager *SM, const LangOptions *langOpts, const clang::Decl *D,
                                bool with_semicolon)
{
    clang::SourceLocation SLoc = SM->getExpansionLoc(D->getLocStart());
    clang::SourceLocation ELoc = SM->getExpansionLoc(D->getLocEnd());
    unsigned start = SM->getFileOffset(SLoc);
    unsigned end = SM->getFileOffset(ELoc);

    // Below code copied from clang::Lexer::MeasureTokenLength():
    clang::SourceLocation Loc = SM->getExpansionLoc(ELoc);
    std::pair<clang::FileID, unsigned> LocInfo = SM->getDecomposedLoc(Loc);
    llvm::StringRef Buffer = SM->getBufferData(LocInfo.first);
    const char *StrData = Buffer.data() + LocInfo.second;
    Lexer TheLexer(Loc, *langOpts, Buffer.begin(), StrData, Buffer.end());
    Token token;
    TheLexer.LexFromRawLexer(token);
    end += token.getLength();

    if (!with_semicolon) {
        return SourceRange(SourceLocation::getFromRawEncoding(start),
                           SourceLocation::getFromRawEncoding(end + 2));
    }

    if (token.isNot(clang::tok::semi) && token.isNot(clang::tok::r_brace)) {
        TheLexer.LexFromRawLexer(token);
        if (token.is(clang::tok::semi)) {
            end += token.getLength();
        }
    }

    return SourceRange(SourceLocation::getFromRawEncoding(start),
                       SourceLocation::getFromRawEncoding(end + 3));
}

void StmtIterator::VisitStmt(Stmt *S)
{

    for (Stmt::child_range C = S->children(); C; ++C) {
        if (*C) {
            Visit(*C);
        }
    }
}

void StmtIterator::VisitDeclStmt(DeclStmt *S)
{

    VisitStmt(S);
    for (DeclStmt::decl_iterator D = S->decl_begin(), DEnd = S->decl_end(); D != DEnd; ++D)
        VisitDecl(*D);
}

void StmtIterator::VisitNullStmt(NullStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitCompoundStmt(CompoundStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitSwitchCase(SwitchCase *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitCaseStmt(CaseStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitCXXForRangeStmt(CXXForRangeStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitArrayTypeTraitExpr(ArrayTypeTraitExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitAsTypeExpr(AsTypeExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitAtomicExpr(AtomicExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCBridgedCastExpr(ObjCBridgedCastExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAutoreleasePoolStmt(clang::ObjCAutoreleasePoolStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitSEHExceptStmt(SEHExceptStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitSEHFinallyStmt(SEHFinallyStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitSEHTryStmt(SEHTryStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitExpressionTraitExpr(ExpressionTraitExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitGenericSelectionExpr(GenericSelectionExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitMaterializeTemporaryExpr(MaterializeTemporaryExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitMSDependentExistsStmt(MSDependentExistsStmt *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitPseudoObjectExpr(clang::PseudoObjectExpr *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitObjCBoolLiteralExpr(clang::ObjCBoolLiteralExpr *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitObjCDictionaryLiteral(clang::ObjCDictionaryLiteral *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitObjCNumericLiteral(clang::ObjCNumericLiteral *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitLambdaExpr(clang::LambdaExpr *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitObjCArrayLiteral(clang::ObjCArrayLiteral *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitTypeTraitExpr(clang::TypeTraitExpr *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitUserDefinedLiteral(clang::UserDefinedLiteral *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitAttributedStmt(clang::AttributedStmt *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitObjCSubscriptRefExpr(clang::ObjCSubscriptRefExpr *S)
{
    VisitStmt(S);
}

void StmtIterator::VisitObjCIndirectCopyRestoreExpr(ObjCIndirectCopyRestoreExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitSubstNonTypeTemplateParmExpr(SubstNonTypeTemplateParmExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitUnaryExprOrTypeTraitExpr(UnaryExprOrTypeTraitExpr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitDefaultStmt(DefaultStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitLabelStmt(LabelStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getDecl());
}

void StmtIterator::VisitIfStmt(IfStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getConditionVariable());
}

void StmtIterator::VisitSwitchStmt(SwitchStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getConditionVariable());
}

void StmtIterator::VisitWhileStmt(WhileStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getConditionVariable());
}

void StmtIterator::VisitDoStmt(DoStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitForStmt(ForStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitGotoStmt(GotoStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getLabel());
}

void StmtIterator::VisitIndirectGotoStmt(IndirectGotoStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitContinueStmt(ContinueStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitBreakStmt(BreakStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitReturnStmt(ReturnStmt *S)
{
    std::cout << "--> VisitReturnStmt()" << std::endl;
    const FunctionDecl *FD = cast<FunctionDecl>(D);

    if (NULL != strstr(FD->getQualifiedNameAsString().c_str(), "std::")) {
        return;
    }

    if (NULL != strstr(FD->getQualifiedNameAsString().c_str(), "_trace_represent")) {
        return;
    }

    if (isa<CXXMethodDecl>(D)) {
        CXXMethodDecl *method_decl = dyn_cast<CXXMethodDecl>(D);
        CXXRecordDecl *class_decl = method_decl->getParent();
        if (class_decl->isDependentType()) {
            return;
        }
    }

    if (!shouldInstrumentFunctionDecl(FD, whitelistExceptions)) {
        return;
    }

    SourceLocation startLoc = S->getLocStart();
    SourceLocation onePastSemiLoc = getReturnStmtEnd(ast, Rewrite, S);

    TraceParam trace_param(Out, Diags, ast, Rewrite);
    TraceParam function_name_param(Out, Diags, ast, Rewrite);
    function_name_param.setConstStr(FD->getQualifiedNameAsString());

    TraceCall trace_call(Out, Diags, ast, Rewrite);
    enum trace_severity severity = TRACE_SEV_FUNC_TRACE;
    trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE");
    trace_call.setSeverity(severity);
    trace_call.addTraceParam(function_name_param);
    if (NULL == S->getRetValue()) {
        goto expand;
    }

    if (trace_param.fromExpr(S->getRetValue(), false) && !(S->getRetValue()->HasSideEffects(ast))) {
        trace_call.addTraceParam(trace_param);
        VisitStmt(S);
    }

expand:
    std::string problem_str = "";
    if (Rewrite->InsertText(onePastSemiLoc, "}", true)) {
        std::cout << "error: couldn't insert }" << std::endl;
    };
    Stmt *stmt = FD->getBody();
    SourceLocation function_start = getFunctionBodyStart(stmt);
    // replace return statement
    std::string expansion = trace_call.getExpansion();
    std::string parameterlist = trace_call.getParameterListStr();
    Rewrite->ReplaceText(
        startLoc, 6, std::string("{") + TRACE_FUNC_EXIT(function_name_param.const_str,
                                                        SM->getPresumedLineNumber(function_start), expansion,
                                                        parameterlist) + problem_str + " return ");
    return;
}

void StmtIterator::VisitAsmStmt(AsmStmt *S)
{

    VisitStmt(S);
    VisitStringLiteral(S->getAsmString());
    for (unsigned I = 0, N = S->getNumOutputs(); I != N; ++I) {
        VisitStringLiteral(S->getOutputConstraintLiteral(I));
    }
    for (unsigned I = 0, N = S->getNumInputs(); I != N; ++I) {
        VisitStringLiteral(S->getInputConstraintLiteral(I));
    }
    for (unsigned I = 0, N = S->getNumClobbers(); I != N; ++I)
        VisitStringLiteral(S->getClobber(I));
}

void StmtIterator::VisitCXXCatchStmt(CXXCatchStmt *S)
{

    VisitStmt(S);
    VisitType(S->getCaughtType());
}

void StmtIterator::VisitCXXTryStmt(CXXTryStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCForCollectionStmt(ObjCForCollectionStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtCatchStmt(ObjCAtCatchStmt *S)
{

    VisitStmt(S);
    if (S->getCatchParamDecl())
        VisitType(S->getCatchParamDecl()->getType());
}

void StmtIterator::VisitObjCAtFinallyStmt(ObjCAtFinallyStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtTryStmt(ObjCAtTryStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtSynchronizedStmt(ObjCAtSynchronizedStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtThrowStmt(ObjCAtThrowStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitExpr(Expr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitDeclRefExpr(DeclRefExpr *S)
{

    VisitExpr(S);
    VisitNestedNameSpecifier(S->getQualifier());
    VisitDecl(S->getDecl());
    VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitPredefinedExpr(PredefinedExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitIntegerLiteral(IntegerLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCharacterLiteral(CharacterLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitFloatingLiteral(FloatingLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitImaginaryLiteral(ImaginaryLiteral *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitStringLiteral(StringLiteral *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitParenExpr(ParenExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitParenListExpr(ParenListExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitUnaryOperator(UnaryOperator *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitOffsetOfExpr(OffsetOfExpr *S)
{

    VisitType(S->getTypeSourceInfo()->getType());
    unsigned n = S->getNumComponents();
    for (unsigned i = 0; i < n; ++i) {
        const OffsetOfExpr::OffsetOfNode &ON = S->getComponent(i);
        switch (ON.getKind()) {
        case OffsetOfExpr::OffsetOfNode::Array:
            // Expressions handled below.
            break;

        case OffsetOfExpr::OffsetOfNode::Field:
            VisitDecl(ON.getField());
            break;

        case OffsetOfExpr::OffsetOfNode::Identifier:
            break;

        case OffsetOfExpr::OffsetOfNode::Base:
            // These nodes are implicit, and therefore don't need profiling.
            break;
        }
    }

    VisitExpr(S);
}

void StmtIterator::VisitArraySubscriptExpr(ArraySubscriptExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCallExpr(CallExpr *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitMemberExpr(MemberExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getMemberDecl());
    VisitNestedNameSpecifier(S->getQualifier());
}

void StmtIterator::VisitCompoundLiteralExpr(CompoundLiteralExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCastExpr(CastExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitImplicitCastExpr(ImplicitCastExpr *S)
{

    VisitCastExpr(S);
}

void StmtIterator::VisitExplicitCastExpr(ExplicitCastExpr *S)
{

    VisitCastExpr(S);
    VisitType(S->getTypeAsWritten());
}

void StmtIterator::VisitCStyleCastExpr(CStyleCastExpr *S)
{

    VisitExplicitCastExpr(S);
}

void StmtIterator::VisitBinaryOperator(BinaryOperator *S)
{

    //    VisitExpr(S);
}

void StmtIterator::VisitCompoundAssignOperator(CompoundAssignOperator *S)
{

    VisitBinaryOperator(S);
}

void StmtIterator::VisitConditionalOperator(ConditionalOperator *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitBinaryConditionalOperator(BinaryConditionalOperator *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitAddrLabelExpr(AddrLabelExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getLabel());
}

void StmtIterator::VisitStmtExpr(StmtExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitShuffleVectorExpr(ShuffleVectorExpr *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitChooseExpr(ChooseExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitGNUNullExpr(GNUNullExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitVAArgExpr(VAArgExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitInitListExpr(InitListExpr *S)
{

    if (S->getSyntacticForm()) {
        VisitInitListExpr(S->getSyntacticForm());
        return;
    }

    VisitExpr(S);
}

void StmtIterator::VisitDesignatedInitExpr(DesignatedInitExpr *S)
{

    VisitExpr(S);
    for (DesignatedInitExpr::designators_iterator D = S->designators_begin(), DEnd = S->designators_end();
         D != DEnd; ++D) {
        if (D->isFieldDesignator()) {
            VisitName(D->getFieldName());
            continue;
        }
    }
}

void StmtIterator::VisitImplicitValueInitExpr(ImplicitValueInitExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitExtVectorElementExpr(ExtVectorElementExpr *S)
{

    VisitExpr(S);
    VisitName(&S->getAccessor());
}

void StmtIterator::VisitBlockExpr(BlockExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getBlockDecl());
}

void StmtIterator::VisitCXXOperatorCallExpr(CXXOperatorCallExpr *S)
{

    if (S->isTypeDependent()) {
        for (unsigned I = 0, N = S->getNumArgs(); I != N; ++I)
            Visit(S->getArg(I));
        return;
    }

    VisitCallExpr(S);
}

void StmtIterator::VisitCXXMemberCallExpr(CXXMemberCallExpr *S)
{

    VisitCallExpr(S);
}

void StmtIterator::VisitCUDAKernelCallExpr(CUDAKernelCallExpr *S)
{

    VisitCallExpr(S);
}

void StmtIterator::VisitCXXNamedCastExpr(CXXNamedCastExpr *S)
{

    VisitExplicitCastExpr(S);
}

void StmtIterator::VisitCXXStaticCastExpr(CXXStaticCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXDynamicCastExpr(CXXDynamicCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXReinterpretCastExpr(CXXReinterpretCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXConstCastExpr(CXXConstCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXBoolLiteralExpr(CXXBoolLiteralExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXNullPtrLiteralExpr(CXXNullPtrLiteralExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXTypeidExpr(CXXTypeidExpr *S)
{

    VisitExpr(S);
    if (S->isTypeOperand())
        VisitType(S->getTypeOperand());
}

void StmtIterator::VisitCXXUuidofExpr(CXXUuidofExpr *S)
{

    VisitExpr(S);
    if (S->isTypeOperand())
        VisitType(S->getTypeOperand());
}

void StmtIterator::VisitCXXThisExpr(CXXThisExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXThrowExpr(CXXThrowExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXDefaultArgExpr(CXXDefaultArgExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getParam());
}

void StmtIterator::VisitCXXBindTemporaryExpr(CXXBindTemporaryExpr *S)
{

    VisitExpr(S);
    VisitDecl(const_cast<CXXDestructorDecl *>(S->getTemporary()->getDestructor()));
}

void StmtIterator::VisitCXXConstructExpr(CXXConstructExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getConstructor());
}

void StmtIterator::VisitCXXFunctionalCastExpr(CXXFunctionalCastExpr *S)
{

    VisitExplicitCastExpr(S);
}

void StmtIterator::VisitCXXTemporaryObjectExpr(CXXTemporaryObjectExpr *S)
{

    VisitCXXConstructExpr(S);
}

void StmtIterator::VisitCXXScalarValueInitExpr(CXXScalarValueInitExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXDeleteExpr(CXXDeleteExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getOperatorDelete());
}

void StmtIterator::VisitCXXNewExpr(CXXNewExpr *S)
{

    VisitExpr(S);
    VisitType(S->getAllocatedType());
    VisitDecl(S->getOperatorNew());
    VisitDecl(S->getOperatorDelete());
}

void StmtIterator::VisitCXXPseudoDestructorExpr(CXXPseudoDestructorExpr *S)
{

    VisitExpr(S);
    VisitNestedNameSpecifier(S->getQualifier());
    VisitType(S->getDestroyedType());
}

void StmtIterator::VisitOverloadExpr(OverloadExpr *S)
{

    VisitExpr(S);
    VisitNestedNameSpecifier(S->getQualifier());
    VisitName(S->getName());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getExplicitTemplateArgs().getTemplateArgs(),
                               S->getExplicitTemplateArgs().NumTemplateArgs);
}

void StmtIterator::VisitUnresolvedLookupExpr(UnresolvedLookupExpr *S)
{

    VisitOverloadExpr(S);
}

void StmtIterator::VisitUnaryTypeTraitExpr(UnaryTypeTraitExpr *S)
{

    VisitExpr(S);
    VisitType(S->getQueriedType());
}

void StmtIterator::VisitBinaryTypeTraitExpr(BinaryTypeTraitExpr *S)
{

    VisitExpr(S);
    VisitType(S->getLhsType());
    VisitType(S->getRhsType());
}

void StmtIterator::VisitDependentScopeDeclRefExpr(DependentScopeDeclRefExpr *S)
{

    VisitExpr(S);
    VisitName(S->getDeclName());
    VisitNestedNameSpecifier(S->getQualifier());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitExprWithCleanups(ExprWithCleanups *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXUnresolvedConstructExpr(CXXUnresolvedConstructExpr *S)
{

    VisitExpr(S);
    VisitType(S->getTypeAsWritten());
}

void StmtIterator::VisitCXXDependentScopeMemberExpr(CXXDependentScopeMemberExpr *S)
{

    if (!S->isImplicitAccess()) {
        VisitExpr(S);
    }
    VisitNestedNameSpecifier(S->getQualifier());
    VisitName(S->getMember());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitUnresolvedMemberExpr(UnresolvedMemberExpr *S)
{

    if (!S->isImplicitAccess()) {
        VisitExpr(S);
    }
    VisitNestedNameSpecifier(S->getQualifier());
    VisitName(S->getMemberName());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitCXXNoexceptExpr(CXXNoexceptExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitPackExpansionExpr(PackExpansionExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitSizeOfPackExpr(SizeOfPackExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getPack());
}

void StmtIterator::VisitSubstNonTypeTemplateParmPackExpr(SubstNonTypeTemplateParmPackExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getParameterPack());
    VisitTemplateArgument(S->getArgumentPack());
}

void StmtIterator::VisitOpaqueValueExpr(OpaqueValueExpr *E)
{

    VisitExpr(E);
}

void StmtIterator::VisitObjCStringLiteral(ObjCStringLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitObjCEncodeExpr(ObjCEncodeExpr *S)
{

    VisitExpr(S);
    VisitType(S->getEncodedType());
}

void StmtIterator::VisitObjCSelectorExpr(ObjCSelectorExpr *S)
{

    VisitExpr(S);
    VisitName(S->getSelector());
}

void StmtIterator::VisitObjCProtocolExpr(ObjCProtocolExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getProtocol());
}

void StmtIterator::VisitObjCIvarRefExpr(ObjCIvarRefExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getDecl());
}

void StmtIterator::VisitObjCPropertyRefExpr(ObjCPropertyRefExpr *S)
{

    VisitExpr(S);
    if (S->isImplicitProperty()) {
        VisitDecl(S->getImplicitPropertyGetter());
        VisitDecl(S->getImplicitPropertySetter());
    } else {
        VisitDecl(S->getExplicitProperty());
    }
    if (S->isSuperReceiver()) {
        VisitType(S->getSuperReceiverType());
    }
}

void StmtIterator::VisitObjCMessageExpr(ObjCMessageExpr *S)
{

    VisitExpr(S);
    VisitName(S->getSelector());
    VisitDecl(S->getMethodDecl());
}

void StmtIterator::VisitObjCIsaExpr(ObjCIsaExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitDecl(Decl *D)
{
}

void StmtIterator::VisitType(QualType T)
{
}

void StmtIterator::VisitName(DeclarationName Name)
{
}

void StmtIterator::VisitNestedNameSpecifier(NestedNameSpecifier *NNS)
{
}

void StmtIterator::VisitTemplateName(TemplateName Name)
{
}

void StmtIterator::VisitTemplateArguments(const TemplateArgumentLoc *Args, unsigned NumArgs)
{

    for (unsigned I = 0; I != NumArgs; ++I)
        VisitTemplateArgument(Args[I].getArgument());
}

void StmtIterator::VisitTemplateArgument(const TemplateArgument &Arg)
{
    // Mostly repetitive with TemplateArgument::Profile!
    switch (Arg.getKind()) {
    case TemplateArgument::Null:
        break;

    case TemplateArgument::Type:
        VisitType(Arg.getAsType());
        break;

    case TemplateArgument::Template:
    case TemplateArgument::TemplateExpansion:
        VisitTemplateName(Arg.getAsTemplateOrTemplatePattern());
        break;

    case TemplateArgument::Declaration:
        VisitDecl(Arg.getAsDecl());
        break;

    case TemplateArgument::Integral:
        VisitType(Arg.getIntegralType());
        break;

    case TemplateArgument::Expression:
        Visit(Arg.getAsExpr());
        break;

    case TemplateArgument::Pack:
        const TemplateArgument *Pack = Arg.pack_begin();
        for (unsigned i = 0, e = Arg.pack_size(); i != e; ++i)
            VisitTemplateArgument(Pack[i]);
        break;
    }
}

class PreCompilationLogsConsumer : public ASTConsumer
{
public:
    llvm::raw_ostream &Out;
    DiagnosticsEngine &Diags;
    raw_ostream *OutFile;
    FileID MainFileID;
    SourceManager *SM;
    std::string InFileName;
    CompilerInstance *compilerInstance;

    PreCompilationLogsConsumer(StringRef inFile, raw_ostream *out, CompilerInstance &CI);

    std::string replaceOnce(std::string result, const std::string &replaceWhat,
                            const std::string &replaceWithWhat)
    {
        const int pos = result.find(replaceWhat);
        if (pos == -1)
            return result;
        result.replace(pos, replaceWhat.size(), replaceWithWhat);
        return result;
    }

    std::string typeSectionName(std::string type_str)
    {
        return "." + replaceAll(type_str, " ", ".");
    }

    std::string stringArrayDefinition(std::string str)
    {
        std::stringstream array_def;
        const char *s = str.c_str();
        array_def << "{";
        while (*s != '\0') {
            array_def << "'" << *s << "' ,";
            s++;
        }

        array_def << "'\\0' }";
        return array_def.str();
    }

    void HandleTranslationUnit(ASTContext &C)
    {
        Rewrite.setSourceMgr(C.getSourceManager(), C.getLangOpts());
        SM = &C.getSourceManager();
        MainFileID = SM->getMainFileID();
        DeclIterator decliterator(Out, Diags, C, &Rewrite, SM, C.getLangOpts());
        decliterator.Visit(C.getTranslationUnitDecl());
        if (const RewriteBuffer *RewriteBuf = Rewrite.getRewriteBufferFor(MainFileID)) {
            *OutFile << std::string(RewriteBuf->begin(), RewriteBuf->end());
        } else {
            StringRef buffer = SM->getBufferData(MainFileID).data();
            *OutFile << std::string(buffer);
        }
    }

private:
    Rewriter Rewrite;
};

PreCompilationLogsConsumer::PreCompilationLogsConsumer(StringRef inFile, raw_ostream *out,
                                                       CompilerInstance &CI)
    : Out(llvm::errs()), Diags(CI.getDiagnostics()), OutFile(out), InFileName(inFile), compilerInstance(&CI)
{
}

class InstrumentCodeAction : public PluginASTAction
{
private:
    raw_ostream *OS;
    StringRef InFile;
    CompilerInstance *CI;

protected:
    ASTConsumer *CreateASTConsumer(CompilerInstance &CI, llvm::StringRef InFile)
    {
        if (raw_ostream *OS = CI.createDefaultOutputFile(false, InFile, "cpp"))
            return new PreCompilationLogsConsumer(InFile, OS, CI);
        else {
            return NULL;
        }
    }

    bool ParseArgs(const CompilerInstance &CI, const std::vector<std::string> &args)
    {
        if (args.size()) {
            // current filename
            cpp_filename = args[0];
        } else {
            cpp_filename = InFile.str();
        }
        return true;
    }

    void PrintHelp(llvm::raw_ostream &ros)
    {
        ros << "\n";
    }
};
}

static FrontendPluginRegistry::Add<InstrumentCodeAction> X("trace-instrument", "Instrument code for traces");
