module.exports = {
	title: 'Signatory - A Tezos Remote Signer',
	tagline: 'Signatory signs your Tezos Ops while protecting your private keys',
	url: 'https://signatory.io',
	baseUrl: '/',
	favicon: 'img/favicon.svg',
	organizationName: 'ecadlabs', // Usually your GitHub org/user name.
	projectName: 'signatory', // Usually your repo name.
	onBrokenLinks: 'warn',
	markdown: {
		mermaid: true,
	},
	themes: ['@docusaurus/theme-mermaid'],
	themeConfig: {
		mermaid: {
			theme: {
				light: 'neutral',
				dark: 'dark',
			},
			options: {
				themeVariables: {
					primaryColor: '#1168bd',
					primaryTextColor: '#ffffff',
					primaryBorderColor: '#7C0000',
					lineColor: '#F8B229',
					secondaryColor: '#666',
					tertiaryColor: '#fff',
					textColor: '#ffffff',
					labelColor: '#ffffff',
					actorTextColor: '#ffffff',
					signalTextColor: '#ffffff',
					noteTextColor: '#ffffff',
				}
			}
		},
		colorMode: {
			defaultMode: 'light',
			disableSwitch: true,
			respectPrefersColorScheme: false,
			// The following value has been deprecated and will need to be re-implemented when dark mode is implemented
			// switchConfig: {
			// 	darkIcon: '🌙',
			// 	darkIconStyle: {
			// 		marginLeft: '2px',
			// 	},
			// 	// Unicode icons such as '\u2600' will work
			// 	// Unicode with 5 chars require brackets: '\u{1F602}'
			// 	lightIcon: '\u{1F602}',
			// 	lightIconStyle: {
			// 		marginLeft: '1px',
			// 	},
			// },
		},
		docs: {
			sidebar: {
			  autoCollapseCategories: true,
			},
		},
		navbar: {
			// hideOnScroll: true,
			logo: {
				alt: 'Signatory Signer for Tezos',
				src: 'img/header-logo.svg',
			},
			items: [
				{
					type: 'doc',
					docId: 'start',
					label: 'Docs',
					position: 'right',
					className: 'header-link button_link',
				},
				{
					href: 'https://github.com/ecadlabs/signatory',
					position: 'right',
					className: 'header-link header-github-link',
					'aria-label': 'GitHub repository',
				},
			],
		},
		footer: {
			links: [
				{
					title: 'Contact',
					items: [
						{
							label: 'Report Issues',
							to: 'https://github.com/ecadlabs/signatory/issues/new/choose',
						},
						{
							label: 'Contribute',
							to: 'https://github.com/ecadlabs/signatory/blob/main/README.md',
						},
					],
				},

				{
					title: 'Community',
					items: [
						{
							label: 'Discord',
							to: 'https://discord.gg/7tJ7f9eJHY',
						},
						{
							label: 'Twitter',
							to: 'https://twitter.com/signatoryio',
						},
						{
							label: 'Code of Conduct',
							to: 'https://github.com/ecadlabs/signatory/blob/main/CODE_OF_CONDUCT.md',
						},
						{
							label: 'GitHub',
							to: 'https://github.com/ecadlabs/signatory',
						},
					],
				},
				{
					title: 'Docs',
					items: [
						{
							label: 'Quick Start',
							to: '/docs/start',
						},
					],
				},
				{
					items: [
						{
							html: `image`,
						},
						{
							html: `
									<p class='footerDescription'>
										A Tezos Remote Signer
									</p>
								  `,
						},
						{
							html: `
									<a class='footerButton' href='https://github.com/ecadlabs/signatory'>
										GITHUB
									</a>
								  `,
						},
						{
							html: `form`,
						},
					],
				},
			],
		},
	},
	presets: [
		[
			'@docusaurus/preset-classic',
			{
				docs: {
					path: '../docs',
					sidebarPath: require.resolve('./sidebars.js'),
					editUrl: 'https://github.com/ecadlabs/signatory/edit/master/website/',
				},
				theme: {
					customCss: [
						require.resolve('./src/css/custom.scss'),
						require.resolve('./src/css/tables.scss'),
						require.resolve('./src/css/admonitions.scss'),
						require.resolve('./src/css/codeBlock.scss'),
						require.resolve('./src/css/tabs.scss'),
						require.resolve('./src/css/mermaid.scss'),
					],
				},
			},
		],
	],
	plugins: ['docusaurus-plugin-sass'],
};
