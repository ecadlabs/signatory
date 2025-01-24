/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  // By default, Docusaurus generates a sidebar from the docs folder structure

  docs: [
    {
      type: "category",
      label: "Start",
      className: "sidebarHeader",
      collapsed: false,
      collapsible: false,
      items: [
        "start",
        "architecture",
        "bakers",
        "cli",
        "remote_policy",
        {
          type: "category",
          label: "Client Authorization",
          collapsed: false,
          items: [`authorized_keys`, `jwt`],
        },
        {
          type: "category",
          label: "Watermark Backends",
          collapsed: false,
          items: [`aws_dynamodb`],
        },
        {
          type: "category",
          label: "Vault Backends",
          collapsed: false,
          items: [
            `hashicorp_vault`,
            `aws_kms`,
            `azure_kms`,
            `gcp_kms`,
            `yubihsm`,
            `ledger`,
            `pkcs11`,
            `file_based`,
          ],
        },
      ],
    },
  ],
};

module.exports = sidebars;
