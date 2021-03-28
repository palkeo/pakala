

/**
 * @file Prettier configuration for Solidity
 * @version 1.0.8
 * @summary base config adapted from AirBNB to minizmie diff churn
 * @overrides solidity settings from Solidity Documentation
 */

module.exports = {
  arrowParens: 'always',
  bracketSpacing: true,
  endOfLine: 'lf',
  printWidth: 100,
  singleQuote: true,
  tabWidth: 2,
  trailingComma: 'all',
  overrides: [
    {
      files: '*.sol',
      options: {
        printWidth: 120,
        tabWidth: 4,
        useTabs: false,
        singleQuote: false,
        bracketSpacing: false,
        explicitTypes: 'always',
      },
    },
  ],
};
