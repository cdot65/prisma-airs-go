import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docs: [
    'index',
    {type: 'category', label: 'Getting started', collapsed: false, items: [
      'getting-started/index', 'getting-started/authentication',
      'getting-started/installation', 'getting-started/configuration', 'getting-started/quick-start',
    ]},
    {type: 'category', label: 'Architecture and contracts', items: [
      'developer/architecture', 'services/oauth-lifecycle', 'guides/provider-patterns',
    ]},
    {type: 'category', label: 'Service guides', items: [
      'services/scan-api', 'services/runtime-api', 'services/model-security-api',
      'services/red-team-api', 'services/ai-gateway-api',
    ]},
    {type: 'category', label: 'Hands-on examples', items: [
      'examples/index', 'examples/runtime-scanning', 'examples/profile-crud',
      'examples/topic-crud', 'examples/api-key-rotation', 'examples/model-security',
      'examples/red-team-inventory', 'examples/red-team-scanning', 'examples/gateway-crud',
    ]},
    {type: 'category', label: 'Validation and troubleshooting', items: [
      'developer/live-verification', 'guides/troubleshooting', 'reference/error-handling',
    ]},
    'developer/releases',
    {type: 'category', label: 'About', items: ['about/release-notes', 'about/license']},
  ],
  api: [
    'reference/api-reference',
    {type: 'category', label: 'Clients and methods', collapsed: false, items: [
      'reference/generated/aisec', 'reference/generated/runtime', 'reference/generated/modelsecurity',
      'reference/generated/redteam', 'reference/generated/gateway',
    ]},
    {type: 'category', label: 'Schema catalogs', items: [
      'reference/generated/modelsecurity-schema', 'reference/generated/redteam-schema',
      'reference/generated/gateway-schema',
    ]},
    'reference/environment-variables', 'reference/error-handling',
  ],
  developers: [
    'developer/development', 'developer/architecture', 'developer/design-parity',
    'developer/live-verification', 'developer/feature-quality', 'developer/releases',
  ],
};
export default sidebars;
