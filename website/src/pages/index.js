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
			description='A Remote Signer for Tezos that keeps your keys in an HSM (Yubi, Azure KMS, Google KMS)<head />'
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
