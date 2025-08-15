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
					'Start by prototyping with an on-disk key; move to HSMs, Cloud KMS, or TEEs when ready.',
			},
			{
				icon: require('../../../static/img/book.svg').default,
				title: 'Protocol‑aware policy enforcement',
				description:
					'Set explicit Tezos policies (kinds, requests, JWT, remote policy). Signatory validates requests and watermarks before delegating to your HSM/KMS/TEE.',
			},
			{
				icon: require('../../../static/img/work-briefcase.svg').default,
				title: 'For bakers, validators, and apps',
				description:
					'Use Signatory for baking/validator infrastructure and application workflows alike—such as exchanges, custodians, or oracles. A single signer enforces policy and watermarks while keys remain in your HSM/KMS/TEE.',
			},
			{
				icon: require('../../../static/img/systems.svg').default,
				title: 'Modular external policy (callback)',
				description: (
					<>
						Integrate bespoke controls without forking Signatory using the remote policy hook. Signatory POSTs operation + metadata; your service returns allow/deny (optionally signed). See <a href="https://signatory.io/docs/remote_policy">Remote Policy</a>.
					</>
				),
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
