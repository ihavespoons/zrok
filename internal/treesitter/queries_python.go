package treesitter

const pythonQuery = `
(function_definition
  name: (identifier) @name) @function

(class_definition
  name: (identifier) @name) @class

(assignment
  left: (identifier) @name) @variable
`
