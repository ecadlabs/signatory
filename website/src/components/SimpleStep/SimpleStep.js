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
			<div className={styles.maintenanceNotice}>
				<div className={styles.maintenanceHeader}>
					<span className={styles.maintenanceBadge}>Maintenance Status</span>
				</div>
				<p>
					Following the Tezos Foundation&apos;s decision to end funding for Signatory in January 2026 (and decline a minimal maintenance-only proposal), ECAD Labs has wound down active Tezos protocol maintenance. Four months after our{' '}
					<a
						href="https://forum.tezosagora.org/t/signatory-remote-signer-end-of-ecad-labs-maintenance/7093"
						target="_blank"
						rel="noopener noreferrer"
					>
						June 2026 announcement
					</a>
					, there remains no transition plan or alternative from the core teams for institutional HSM, Cloud KMS, or TEE (<code>tz4</code>/BLS) custody.
				</p>
				<p>
					To avoid leaving production operators exposed to recent Go stdlib and network vulnerabilities, ECAD Labs published{' '}
					<a
						href="https://github.com/ecadlabs/signatory/releases/tag/v1.4.1"
						target="_blank"
						rel="noopener noreferrer"
					>
						<strong><code>v1.4.1</code></strong>
					</a>{' '}
					(October 2026) at our own expense. However, we do not ship untested security claims:{' '}
					<strong>
						<code>v1.4.1</code> is validated through <code>PtTALLiN</code> (<code>octez-v24.4</code>) and has not been tested by ECAD Labs against the Ushuaia (<code>PsUshuai</code>) protocol.
					</strong>{' '}
					See the{' '}
					<a
						href="https://forum.tezosagora.org/t/signatory-remote-signer-end-of-ecad-labs-maintenance/7093"
						target="_blank"
						rel="noopener noreferrer"
					>
						Agora thread
					</a>{' '}
					for context and migration options, or contact{' '}
					<a href="mailto:info@ecadlabs.com">info@ecadlabs.com</a> for commercial support.
				</p>
			</div>
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
