import React from 'react';
import classnames from 'classnames';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './styles.module.css';
import FooterTop from '../components/FooterTop/FooterTop';
import Hero from '../components/Hero/Hero';
import SimpleStep from '../components/SimpleStep/SimpleStep';


function Home() {
	const context = useDocusaurusContext();
	const { siteConfig = {} } = context;
	return (
		<Layout
			title={`${siteConfig.title}`}
			description='Protocol‑aware remote signer for Tezos. Signatory acts as a security boundary, enforcing Tezos policy and watermarks before delegating signing to your HSM, KMS, or TEE (YubiHSM, Azure KMS, Google KMS, AWS Nitro Enclaves, Google Confidential Space).'
		>
			<main>
				<Hero />
				<SimpleStep />
				<FooterTop />
			</main>
		</Layout>
	);
}

export default Home;
