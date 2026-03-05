package treesitter

const cQuery = `
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name)) @function

(function_definition
  declarator: (pointer_declarator
    declarator: (function_declarator
      declarator: (identifier) @name))) @function

(struct_specifier
  name: (type_identifier) @name) @struct

(enum_specifier
  name: (type_identifier) @name) @type

(declaration
  declarator: (init_declarator
    declarator: (identifier) @name)) @variable

(preproc_def
  name: (identifier) @name) @constant

(preproc_function_def
  name: (identifier) @name) @constant
`
