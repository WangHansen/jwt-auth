module.exports = {
  env: {
    es6: true,
    node: true
  },
  extends: [
    "eslint:recommended",
    "plugin:prettier/recommended",
    "plugin:@typescript-eslint/eslint-recommended",
    "plugin:@typescript-eslint/recommended"
  ],
  plugins: ["@typescript-eslint"],
  globals: {
    Atomics: "readonly",
    SharedArrayBuffer: "readonly"
  },
  parserOptions: {
    ecmaVersion: 2018,
    sourceType: "module"
  },
  parser: "@typescript-eslint/parser",
  rules: {}
};
