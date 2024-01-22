const withNextra = require('nextra')({
  theme: 'nextra-theme-docs',
  themeConfig: './theme.config.tsx',
  latex: { renderer: 'mathjax' },
})

module.exports = withNextra()
