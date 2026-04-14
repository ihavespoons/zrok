package treesitter

const javascriptQuery = `
(function_declaration
  name: (identifier) @name) @function

(class_declaration
  name: (identifier) @name) @class

(method_definition
  name: (property_identifier) @name) @method

(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: (arrow_function))) @function

(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: (function_expression))) @function

(variable_declaration
  (variable_declarator
    name: (identifier) @name
    value: (arrow_function))) @function

(variable_declaration
  (variable_declarator
    name: (identifier) @name
    value: (function_expression))) @function
`

const typescriptQuery = `
(function_declaration
  name: (identifier) @name) @function

(class_declaration
  name: (type_identifier) @name) @class

(method_definition
  name: (property_identifier) @name) @method

(interface_declaration
  name: (type_identifier) @name) @interface

(type_alias_declaration
  name: (type_identifier) @name) @type

(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: (arrow_function))) @function

(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: (function_expression))) @function

(variable_declaration
  (variable_declarator
    name: (identifier) @name
    value: (arrow_function))) @function

(variable_declaration
  (variable_declarator
    name: (identifier) @name
    value: (function_expression))) @function

(enum_declaration
  name: (identifier) @name) @type
`
