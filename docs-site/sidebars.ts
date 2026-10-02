import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docs: [
    'index',
    {type: 'category', label: 'Getting Started', collapsed: false, items: [
      'getting-started/installation', 'getting-started/configuration',
      'reference/environment-variables', 'getting-started/quick-start',
    ]},
    {type: 'category', label: 'Guides', items: [
      'services/scan-api', 'services/runtime-api', 'services/model-security-api',
      'services/red-team-api', 'services/ai-gateway-api', 'services/oauth-lifecycle',
    ]},
    {type: 'category', label: 'Examples', items: [
      'examples/runtime-scanning', 'examples/profile-crud', 'examples/topic-crud',
      'examples/red-team-scanning', 'examples/api-key-rotation',
    ]},
    {type: 'category', label: 'About', items: ['about/release-notes', 'about/license']},
  ],
  api: ['reference/api-reference', 'reference/error-handling'],
  developers: [
    'developer/architecture', 'developer/live-verification',
    'developer/feature-quality', 'developer/releases',
  ],
};
export default sidebars;
