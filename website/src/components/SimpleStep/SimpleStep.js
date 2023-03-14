import React from 'react';
import clsx from 'clsx';
import styles from './SimpleStep.module.scss';

const FeatureList = [
	{
		steps: [
			{
				icon: require('../../../static/img/hand.svg').default,
				title: 'Easy to start, trivial to secure',
				description:
					'Start prototyping your infrastructure with an on-disk key, switch to an HSM when it makes sense.',
			},
			{
				icon: require('../../../static/img/book.svg').default,
				title: 'Signatory signs only the operations you want',
				description:
					'Set policy on the type of Tezos Operations you want to allow signing. Are you running a baker? Limit it to blocks and endorsements. Institution? Signatory can enforce policies.',
			},
			{
				icon: require('../../../static/img/lenz.svg').default,
				title: 'Built with observability',
				description:
					'Critical infrastructure monitoring is crucial. Signatory exposes operational metrics for Prometheus allowing teams to monitor operations with the tools they have already invested in.',
			},
		],
	},
];

function Feature({ steps }) {
	return (
		<div className={styles.content}>
			<div className={styles.simpleStepsContainer}>
				<div className={styles.steps}>
					{steps.map((step, idx) => (
						<div
							className={
								idx % 2 === 0
									? styles.stepContainerLeft
									: styles.stepContainerRight
							}
							key={idx}
						>
							<div className={styles.stepBox}>
								<step.icon alt={step.title} />
								<div className={styles.textContainer}>
									<h4 className={styles.stepTitle}>{step.title}</h4>
									<p className={styles.stepDescription}>{step.description}</p>
								</div>
							</div>
						</div>
					))}
				</div>
			</div>
		</div>
	);
}

export default function SimpleStep() {
	return (
		<section className={styles.features}>
			<div className={styles.container}>
				<Feature {...FeatureList[0]} />
			</div>
		</section>
	);
}
