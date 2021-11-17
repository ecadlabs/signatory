import React from 'react';
import classnames from 'classnames';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './styles.module.css';

const features = [
  {
    title: <>Easy to start, trivial to secure</>,
    imageUrl: 'img/undraw_security_o890.svg',
    description: (
      <>
        Start prototyping your infrastructure with an on-disk key, switch to a HSM when it makes sense
      </>
    ),
  },
  {
    title: <>Signatory signs only the operations you want</>,
    imageUrl: 'img/undraw_data_processing_yrrv.svg',
    description: (
      <>
        Set policy on the type of Tezos Operations you want to allow signing. Are you running a baker? Limit it to blocks and endorsements. Institution? Signatory can enforce policies.
      </>
    ),
  },
  {
    title: <>Built with observability</>,
    imageUrl: 'img/undraw_observations_mejb.svg',
    description: (
      <>
        Critical infrastructure monitoring is crucial. Signatory exposes operational metrics for Prometheus allowing teams to monitor operations with the tools they have already invested in
      </>
    ),
  },
];

function Feature({imageUrl, title, description}) {
  const imgUrl = useBaseUrl(imageUrl);
  return (
    <div className={classnames('col col--4', styles.feature)}>
      {imgUrl && (
        <div className="text--center">
          <img className={styles.featureImage} src={imgUrl} alt={title} />
        </div>
      )}
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}

function Home() {
  const context = useDocusaurusContext();
  const {siteConfig = {}} = context;
  return (
    <Layout
      title={`${siteConfig.title}`}
      description="A Remote Signer for Tezos that keeps your keys in a HSM (Yubi, Azure KMS, Google KMS)<head />">
      <header className={classnames('hero hero--primary', styles.heroBanner)}>
        <div className="container">
          <h1 className="hero__title">{siteConfig.title}</h1>
          <p className="hero__subtitle">{siteConfig.tagline}</p>
          <div className={styles.buttons}>
            <Link
              className={classnames(
                'button button--outline button--secondary button--lg',
                styles.getStarted,
              )}
              to={useBaseUrl('docs/start')}>
              Get Started
            </Link>
          </div>
        </div>
      </header>
      <main>
        {features && features.length && (
          <section className={styles.features}>
            <div className="container">
              <div className="row">
                {features.map((props, idx) => (
                  <Feature key={idx} {...props} />
                ))}
              </div>
            </div>
          </section>
        )}
      </main>
    </Layout>
  );
}

export default Home;
