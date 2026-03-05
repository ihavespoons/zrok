package treesitter

const javaQuery = `
(class_declaration
  name: (identifier) @name) @class

(interface_declaration
  name: (identifier) @name) @interface

(method_declaration
  name: (identifier) @name) @method

(constructor_declaration
  name: (identifier) @name) @function

(enum_declaration
  name: (identifier) @name) @type

(field_declaration
  declarator: (variable_declarator
    name: (identifier) @name)) @variable
`
