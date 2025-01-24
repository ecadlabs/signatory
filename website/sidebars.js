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
        "authorized_keys",
        "aws_dynamodb",
        "aws_kms",
        "azure_kms",
        "bakers",
        "cli",
        "file_based",
        "gcp_kms",
        "hashicorp_vault",
        "jwt",
        "ledger",
        "pkcs11",
        "remote_policy",
        "yubihsm",
        {
          type: "category",
          label: "Client Authorization",
          items: [`authorized_keys`, `jwt`],
        },
      ],
    },
  ],
};

module.exports = sidebars;
