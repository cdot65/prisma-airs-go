import React, {type ReactNode} from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './index.module.css';

const paths = [
  ['01', 'Send your first scan', 'Install the SDK, configure credentials, choose a profile, and verify a real response.', '/getting-started/'],
  ['02', 'Understand the SDK', 'Follow the service boundaries, authentication, request pipeline, and response contracts.', '/developer/architecture/'],
  ['03', 'Manage your gateway', 'Use SCM OAuth for configurations, policies, integrations, and existing workspaces.', '/examples/gateway-crud/'],
  ['04', 'Explore AgentGuard preview', 'Inspect skill scans, vulnerabilities, attack chains, and statistics with the public preview client.', '/examples/agentguard-scanning/'],
];

export default function Home(): ReactNode {
  return (
    <Layout title="Go clients for Prisma AIRS" description="Prisma AIRS Go SDK: typed clients for Runtime Security, Model Security, Red Team, AI Gateway management, and AgentGuard public preview, using the Go standard library.">
      <main>
        <section className={styles.hero} aria-labelledby="hero-title">
          <div className={styles.heroCopy}>
            <p className={styles.eyebrow}>PRISMA AIRS / GO SDK</p>
            <h1 id="hero-title">Local control.<br /><span>Gateway intelligence.</span></h1>
            <p className={styles.lead}>A Go SDK built for Prisma AIRS. Bring your tenant, configure your credentials, and use typed security clients, gateway management, and the AgentGuard preview.</p>
            <div className={styles.actions}>
              <Link className="button button--primary button--lg" to="/getting-started/">Get started →</Link>
              <Link className={styles.secondary} to="/developer/architecture/">Explore the architecture ↗</Link>
            </div>
            <p className={styles.platforms}>GO 1.22+ · STANDARD LIBRARY · MIT LICENSED</p>
          </div>
          <div className={styles.artwork}>
            <img src={useBaseUrl('/img/brand-logo.png')} alt="Prisma AIRS shield and prism spectrum" width="1254" height="1254" fetchPriority="high" />
            <div className={styles.pillRow}><span className={styles.pill}>SCM OAuth</span><span className={styles.pill}>Typed clients</span><span className={styles.pill}>Gateway CRUD</span></div>
          </div>
        </section>
        <section className={styles.paths} aria-labelledby="paths-title">
          <div className={styles.sectionIntro}><p className={styles.eyebrow}>FROM FIRST SCAN TO OPERATIONS</p><h2 id="paths-title">A clear path through the platform.</h2><p>Start with the task in front of you. Each guide includes the context, configuration, and checks you need.</p></div>
          <div className={styles.grid}>{paths.map(([number, title, description, to]) => <Link className={styles.path} to={to} key={number}><span className={styles.number}>{number}</span><h3>{title}</h3><p>{description}</p><span className={styles.arrow} aria-hidden="true">↗</span></Link>)}</div>
        </section>
        <section className={styles.quick}><div><p className={styles.eyebrow}>KEEP IT CLOSE</p><h2>Less searching. More doing.</h2><p>Copy the examples for daily work, or look up the exact methods shipped with the SDK.</p></div><div className={styles.actions}><Link className="button button--primary" to="/examples/">Open the examples</Link><Link to="/reference/api-reference/">API reference →</Link></div></section>
      </main>
    </Layout>
  );
}
