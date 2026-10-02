import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';
import airsTheme from './src/css/prism-airs';

const config: Config = {
  title: 'Prisma AIRS Go SDK',
  tagline: 'Go clients for Prisma AIRS security and AI Gateway management',
  favicon: 'img/brand-logo.png',
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
    docs: {path: '../docs', sidebarPath: './sidebars.ts', routeBasePath: '/', exclude: ['agents/**', 'superpowers/**']},
    blog: false,
    theme: {customCss: './src/css/custom.css'},
  } satisfies Preset.Options]],
  themeConfig: {
    mermaid: {theme: {light: 'dark', dark: 'dark'}, options: {themeVariables: {
      background: '#030609', primaryColor: '#061b29', primaryTextColor: '#f5f8fa',
      primaryBorderColor: '#00ddf2', lineColor: '#8999a6', secondaryColor: '#0b293b', tertiaryColor: '#061b29',
    }}},
    docs: {sidebar: {hideable: true}},
    colorMode: {defaultMode: 'dark', disableSwitch: true, respectPrefersColorScheme: false},
    navbar: {
      title: 'Prisma AIRS Go SDK',
      logo: {alt: 'Prisma AIRS Go SDK', src: 'img/brand-logo.png'},
      items: [
        {type: 'docSidebar', sidebarId: 'docs', label: 'Docs', position: 'left'},
        {type: 'docSidebar', sidebarId: 'api', label: 'API Reference', position: 'left'},
        {type: 'docSidebar', sidebarId: 'developers', label: 'Developers', position: 'left'},
        {href: 'https://github.com/cdot65/prisma-airs-go', label: 'GitHub', position: 'right'},
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {title: 'Go SDK', items: [
          {label: 'Getting Started', to: '/getting-started/'},
          {label: 'API Reference', to: '/reference/api-reference/'},
          {label: 'Releases', to: '/developer/releases/'},
        ]},
        {title: 'Prisma AIRS', items: [
          {label: 'CLI', href: 'https://cdot65.github.io/prisma-airs-cli/'},
          {label: 'TypeScript SDK', href: 'https://cdot65.github.io/prisma-airs-sdk/'},
          {label: 'Harness', href: 'https://cdot65.github.io/prisma-airs-harness/'},
        ]},
        {title: 'Source', items: [
          {label: 'GitHub · issues and contributions', href: 'https://github.com/cdot65/prisma-airs-go/issues'},
          {label: 'Go package reference', href: 'https://pkg.go.dev/github.com/cdot65/prisma-airs-go/aisec'},
        ]},
      ],
      copyright: `Copyright © ${new Date().getFullYear()} cdot65. Go SDK: MIT. Built with Docusaurus.`,
    },
    prism: {theme: airsTheme, darkTheme: airsTheme,
      additionalLanguages: ['go', 'bash', 'json', 'yaml', 'python', 'powershell', 'toml', 'diff', 'rust']},
  } satisfies Preset.ThemeConfig,
};
export default config;
