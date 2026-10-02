import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';
import airsTheme from './src/css/prism-airs';

const config: Config = {
  title: 'Prisma AIRS Go SDK',
  tagline: 'Go clients for Prisma AIRS security and AI Gateway management',
  favicon: 'img/logo.svg',
  url: 'https://cdot65.github.io',
  baseUrl: '/prisma-airs-go/',
  organizationName: 'cdot65',
  projectName: 'prisma-airs-go',
  future: {v4: true},
  trailingSlash: true,
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',
  markdown: {format: 'detect', mermaid: true, hooks: {onBrokenMarkdownLinks: 'throw'}},
  themes: ['@docusaurus/theme-mermaid'],
  i18n: {defaultLocale: 'en', locales: ['en']},
  presets: [['classic', {
    docs: {
      path: '../docs',
      sidebarPath: './sidebars.ts',
      routeBasePath: '/',
      exclude: ['agents/**', 'superpowers/**'],
      editUrl: ({docPath}) => `https://github.com/cdot65/prisma-airs-go/edit/main/docs/${docPath}`,
    },
    blog: false,
    theme: {customCss: './src/css/custom.css'},
  } satisfies Preset.Options]],
  themeConfig: {
    docs: {sidebar: {hideable: true}},
    colorMode: {defaultMode: 'dark', disableSwitch: true, respectPrefersColorScheme: false},
    mermaid: {theme: {light: 'dark', dark: 'dark'}, options: {themeVariables: {
      background: '#030609', primaryColor: '#061b29', primaryTextColor: '#f5f8fa',
      primaryBorderColor: '#00ddf2', lineColor: '#8999a6', secondaryColor: '#0b293b', tertiaryColor: '#061b29',
    }}},
    navbar: {
      title: 'Prisma AIRS Go SDK',
      logo: {alt: 'Prisma AIRS', src: 'img/logo.svg'},
      items: [
        {type: 'docSidebar', sidebarId: 'docs', label: 'Docs', position: 'left'},
        {type: 'docSidebar', sidebarId: 'api', label: 'API Reference', position: 'left'},
        {type: 'docSidebar', sidebarId: 'developers', label: 'Developers', position: 'left'},
        {href: 'https://pkg.go.dev/github.com/cdot65/prisma-airs-go/aisec', label: 'pkg.go.dev', position: 'right'},
        {href: 'https://github.com/cdot65/prisma-airs-go', label: 'GitHub', position: 'right'},
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {title: 'Go SDK', items: [
          {label: 'Getting Started', to: '/getting-started/installation/'},
          {label: 'API Reference', to: '/reference/api-reference/'},
          {label: 'Release Downloads', to: '/developer/releases/'},
        ]},
        {title: 'Prisma AIRS', items: [
          {label: 'TypeScript SDK', href: 'https://cdot65.github.io/prisma-airs-sdk/'},
          {label: 'CLI', href: 'https://cdot65.github.io/prisma-airs-cli/'},
          {label: 'Harness', href: 'https://cdot65.github.io/prisma-airs-harness/'},
        ]},
        {title: 'Source', items: [
          {label: 'GitHub', href: 'https://github.com/cdot65/prisma-airs-go'},
          {label: 'Go Package Reference', href: 'https://pkg.go.dev/github.com/cdot65/prisma-airs-go/aisec'},
        ]},
      ],
      copyright: `Copyright © ${new Date().getFullYear()} cdot65. Go SDK: MIT. Built with Docusaurus.`,
    },
    prism: {theme: airsTheme, darkTheme: airsTheme, additionalLanguages: ['go', 'bash', 'json', 'yaml', 'diff']},
  } satisfies Preset.ThemeConfig,
};
export default config;
