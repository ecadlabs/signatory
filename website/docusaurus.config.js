module.exports = {
  title: 'Signatory - A Tezos Remote Signer',
  tagline: 'Signatory signs your Tezos Ops while protecting your private keys',
  url: 'https://signatory.io',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  organizationName: 'ecadlabs', // Usually your GitHub org/user name.
  projectName: 'signatory', // Usually your repo name.
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
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Getting Started ',
              to: 'docs/start',
            },
            {
              label: 'Local Secret',
              to: 'docs/filebased',
            },
            {
              label: 'YubiHSM',
              to: 'docs/yubihsm',
            },
            {
              label: 'Azure KMS',
              to: 'docs/azure_kms',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'Tezos Stack Overflow',
              href: 'https://tezos.stackexchange.com/questions/tagged/remote-signer',
            },
          ],
        },
        {
          title: 'Social',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/ecadlabs/signatory',
            },
            {
              label: 'Twitter',
              href: 'https://twitter.com/signatoryio',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} ECAD Labs Inc.`,
    },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          path: '../docs',
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl:
            'https://github.com/ecadlabs/signatory/edit/main/website/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
};
