package treesitter

const rustQuery = `
(function_item
  name: (identifier) @name) @function

(struct_item
  name: (type_identifier) @name) @struct

(enum_item
  name: (type_identifier) @name) @type

(trait_item
  name: (type_identifier) @name) @interface

(impl_item
  trait: (type_identifier) @name) @type

(type_item
  name: (type_identifier) @name) @type

(const_item
  name: (identifier) @name) @constant

(static_item
  name: (identifier) @name) @variable
`
