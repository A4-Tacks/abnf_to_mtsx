" Vim syntax file
" Language:		MT-Syntax (mtsx)
" Maintainer:		A4-Tacks <wdsjxhno1001@163.com>
" Last Change:		2023-12-13
" URL:		https://github.com/A4-Tacks/abnf_to_mtsx

if exists("b:current_syntax")
    finish
endif

" debug clear
"syn clear

" 大小写敏感
syn case match

setlocal comments=://
setlocal commentstring=//%s


syn region mtsyntaxString start=/"/ end=/"\|$/ contains=mtsyntaxStrEscape,mtsyntaxStrFailEscape
syn match mtsyntaxStrFailEscape /\\./ contained
syn match mtsyntaxStrEscape /\\\(x\x\x\|u\x\{4}\|[f'"\\tbnr]\)/ contained
hi link mtsyntaxString String
hi link mtsyntaxStrEscape SpecialChar
hi link mtsyntaxStrFailEscape Error

syn region mtsyntaxRegex start="/" end="/\|$" contains=mtsyntaxRegexEscape
syn match mtsyntaxRegexEscape "\\/" contained
hi link mtsyntaxRegex String
hi link mtsyntaxRegexEscape SpecialChar

syn match mtsyntaxBuiltin /#[0-9A-Z_]\+#/
syn match mtsyntaxColor /#\x\{3,8}\>/
syn match mtsyntaxRegexGroup /\v<(0|[1-9]\d*)>/
syn match mtsyntaxBoolean /\v<(true|false)>/
hi link mtsyntaxBuiltin Constant
hi link mtsyntaxColor Number
hi link mtsyntaxRegexGroup Number
hi link mtsyntaxBoolean Number

syn match mtsyntaxGroup /\v<group>[ \t]*:?[ \t]*/ nextgroup=mtsyntaxGroupValue
syn match mtsyntaxGroupValue /\v<(link(All)?|select)>/ contained
hi link mtsyntaxGroup Keyword
hi link mtsyntaxGroupValue Number

syn match mtsyntaxBuiltinFunction /\v<(keywordsToRegex)>/
hi link mtsyntaxBuiltinFunction Operator

syn keyword mtsyntaxKeywords
            \ match name comment insertSpace \contains color
            \ colors start end startsWith endsWith builtin
            \ matchEndFirst codeFormatter codeShrinker
            \ lineBackground ignoreCase hide addToContains
            \ number iSuffixes fSuffixes recordAllGroups
            \ defines include
hi link mtsyntaxKeywords Keyword

syn match mtsyntaxComment /\/\/.*/
hi link mtsyntaxComment Comment

syn region mtsyntaxBlock start=/{/ end=/}/ transparent fold
syn region mtsyntaxList start=/\[/ end=/\]/ transparent fold

syn match mtsyntaxPreProc +\v//!(BEGIN|END|COLOR(DEF)=|NOOPT|CODE)>+
hi link mtsyntaxPreProc PreProc

syn region mtsyntaxABNFString start=/\(%[si]\)\="/ end=/"\|$/ contains=mtsyntaxABNFStrEscape,mtsyntaxABNFStrFailEscape
syn match mtsyntaxABNFStrFailEscape /\\./ contained
syn match mtsyntaxABNFStrEscape /\\\(x\x\x\|u\x\{4}\|[f'"\\tbnr]\)/ contained
hi link mtsyntaxABNFString String
hi link mtsyntaxABNFStrEscape SpecialChar
hi link mtsyntaxABNFStrFailEscape Error

syn region mtsyntaxABNF start=+//!BEGIN+ end=+\(//!END\)\@<=+ fold contains=mtsyntaxABNFProse,mtsyntaxABNFComment,mtsyntaxPreProc,mtsyntaxABNFString,mtsyntaxABNFNumVal,mtsyntaxColor,mtsyntaxABNFRepeat
syn region mtsyntaxABNFProse start=/</ end=/>\|$/ contained
syn match mtsyntaxABNFComment /;.*/ contained
syn match mtsyntaxABNFNumVal /\v\%(b[01]+((\.[01]+)+|\-[01]+)=|d\d+((\.\d+)+|\-\d+)=|x\x+((\.\x+)+|\-\x+)=)/ contained
syn match mtsyntaxABNFRepeat /\v\d+|\d*\*\d*/ contained
hi link mtsyntaxABNFProse String
hi link mtsyntaxABNFComment Comment
hi link mtsyntaxABNFNumVal Number
hi link mtsyntaxABNFRepeat Number
