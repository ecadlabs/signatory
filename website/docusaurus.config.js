module.exports = {
	title: 'Signatory - A Tezos Remote Signer',
	tagline: 'Signatory signs your Tezos Ops while protecting your private keys',
	url: 'https://signatory.io',
	baseUrl: '/',
	favicon: 'img/favicon.ico',
	organizationName: 'ecadlabs', // Usually your GitHub org/user name.
	projectName: 'signatory', // Usually your repo name.
	onBrokenLinks: 'warn',
	themeConfig: {
		navbar: {
			title: 'Signatory Remote Signer',
			logo: {
				alt: 'Signatory Signer for Tezos',
				src: 'img/logo_nib.png',
			},
			items: [
				{
					to: 'docs/start',
					activeBasePath: 'docs',
					label: 'Docs',
					position: 'left',
				},
				{
					href: 'https://github.com/ecadlabs/signatory',
					label: 'GitHub',
					position: 'right',
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
							to: 'https://github.com/ecadlabs/taqueria/issues/new/choose',
						},
						{
							label: 'Contribute',
							to: 'https://github.com/ecadlabs/taquito/blob/master/CONTRIBUTING.md',
						},
					],
				},

				{
					title: 'Community',
					items: [
						{
							label: 'Stack Exchange',
							to: 'https://tezos.stackexchange.com/questions/tagged/taqueria',
						},
						{
							label: 'Discord',
							to: 'https://discord.gg/bujt7syVVT',
						},
						{
							label: 'Twitter',
							to: 'https://twitter.com/tezostaqueria',
						},
						{
							label: 'Code of Conduct',
							to: 'https://github.com/ecadlabs/taquito/blob/master/code-of-conduct.md',
						},
						{
							label: 'GitHub',
							to: 'https://github.com/ecadlabs/taqueria',
						},
					],
				},
				{
					title: 'Docs',
					items: [
						{
							label: 'Quick Start',
							to: '/docs/quick_start',
						},
						{
							label: 'TypeDoc Reference',
							to: 'https://tezostaquito.io/typedoc',
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
										Faplaren krorar whataboutism. Krorat kroligen. 
									</p>
								  `,
						},
						{
							html: `
									<a class='footerButton' href='https://github.com/ecadlabs/taqueria'>
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
					customCss: require.resolve('./src/css/custom.scss'),
				},
			},
		],
	],
	plugins: ['docusaurus-plugin-sass'],
};
