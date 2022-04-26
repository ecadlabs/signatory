import React, { useState, useEffect } from 'react';
// import clsx from "clsx";
import styles from './Hero.module.scss';
// import Slider from "react-slick";

// import SVGExample from './example-logo.svg'

const FeatureList = [
	{
		title: 'A Tezos Remote Signer',
		// Svg: require("./example-logo.svg").default,
		// SvgTraiangle1: require("../../../static/img/triangle1.svg").default,
		// SvgTraiangle2: require("../../../static/img/triangle2.svg").default,
		// SvgTraiangle3: require("../../../static/img/triangle3.svg").default,
		// SvgTraiangle4: require("../../../static/img/triangle4.svg").default,
		// SvgTraiangle5: require("./example-logo.svg").default,
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
