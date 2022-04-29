import React from 'react';
import styles from './Hero.module.scss';

const FeatureList = [
	{
		title: 'A Tezos Remote Signer',
		description: (
			<>Signatory signs your Tezos Ops while protecting your private keys</>
		),
		link: {
			title: 'Get Started',
			url: '/docs/start',
		},
		Image: require('../../../static/img/place-holder.png').default,
	},
];

function Feature({ title, description, link, Image }) {
	return (
		<div className={styles.content}>
			<div className={styles.heroCardContainer}>
				<div className={styles.heroCard}>
					<h1 className={styles.heroTitle}>{title}</h1>
					<div className={styles.heroCardContent}>
						<p className={styles.heroCardDescription}>{description}</p>
						<div className={styles.heroButtonContainer}>
							<a className={styles.heroButton} href={link.url}>
								{link.title}
							</a>
						</div>
						{link.tilte}
					</div>
				</div>
			</div>
			<div className={styles.carouselContainer}>
				<div className={styles.carousel}>
					{/* image */}
					<img src={Image} alt='' />
				</div>
			</div>
		</div>
	);
}

export default function Hero() {
	const Logo = require('../../../static/img/example.png').default;

	return (
		<section className={styles.features}>
			<div className={styles.container}>
				<Feature {...FeatureList[0]} />
			</div>
		</section>
	);
}
