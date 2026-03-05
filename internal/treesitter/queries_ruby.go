package treesitter

const rubyQuery = `
(class
  name: (constant) @name) @class

(module
  name: (constant) @name) @module

(method
  name: (identifier) @name) @method

(singleton_method
  name: (identifier) @name) @method

(assignment
  left: (constant) @name) @constant
`
