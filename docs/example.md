import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

## List of community-run nodes

_If you are aware of a public node missing from our list or our information is inaccurate, please help us by submitting an issue or pull request on our GitHub page._

| Provider         | Net         | URL                                | Header                                                                    |
| ---------------- | ----------- | ---------------------------------- | ------------------------------------------------------------------------- |
| ECAD Labs        | Mainnet     | https://mainnet.api.tez.ie         | [Check](https://mainnet.api.tez.ie/chains/main/blocks/head/header)        |
| ECAD Labs        | Hangzhounet | https://hangzhounet.api.tez.ie     | [Check](https://hangzhounet.api.tez.ie/chains/main/blocks/head/header)    |
| ECAD Labs        | Ithacanet   | https://ithacanet.ecadinfra.com    | [Check](https://ithacanet.ecadinfra.com/chains/main/blocks/head/header)   |
| SmartPy          | Mainnet     | https://mainnet.smartpy.io         | [Check](https://mainnet.smartpy.io/chains/main/blocks/head/header)        |
| SmartPy          | Hangzhounet | https://hangzhounet.smartpy.io/    | [Check](https://hangzhounet.smartpy.io/chains/main/blocks/head/header)    |
| SmartPy          | Ithacanet   | https://ithacanet.smartpy.io/      | [Check](https://ithacanet.smartpy.io/chains/main/blocks/head/header)      |
| Tezos Foundation | Mainnet     | https://rpc.tzbeta.net/            | [Check](https://rpc.tzbeta.net/chains/main/blocks/head/header)            |
| Tezos Foundation | Ithacanet   | https://rpczero.tzbeta.net/        | [Check](https://rpczero.tzbeta.net/chains/main/blocks/head/header)        |
| LetzBake!        | Mainnet     | https://teznode.letzbake.com       | [Check](https://teznode.letzbake.com/chains/main/blocks/head/header)      |
| GigaNode         | Mainnet     | https://mainnet-tezos.giganode.io  | [Check](https://mainnet-tezos.giganode.io/chains/main/blocks/head/header) |
| GigaNode         | Hangzhounet | https://testnet-tezos.giganode.io/ | [Check](https://testnet-tezos.giganode.io/chains/main/blocks/head/header) |

:::note

Some **content** with _markdown_ `syntax`. Check [this `api`](#).

:::

:::tip

Some **content** with _markdown_ `syntax`. Check [this `api`](#).

:::

:::info

Some **content** with _markdown_ `syntax`. Check [this `api`](#).

:::

:::caution

Some **content** with _markdown_ `syntax`. Check [this `api`](#).

:::

:::danger

Some **content** with _markdown_ `syntax`. Check [this `api`](#).

:::

```js live noInline
// import { TezosToolkit } from '@taquito/taquito'
// import { InMemorySigner } from '@taquito/signer'
// const Tezos = new TezosToolkit('https://ithacanet.ecadinfra.com');
const compileContract = (opts) => (sourceFile) =>
	execCmd(getCompileCommand(opts)(sourceFile)).then(() => ({
		contract: sourceFile,
		artifact: getContractArtifactFilename(opts)(sourceFile),
	}));

const compileAll = (parsedArgs) => {
	// TODO: Fetch list of files from SDK
	return glob(['**/*.ligo', '**/*.religo', '**/*.mligo', '**/*.jsligo'], {
		cwd: parsedArgs.contractsDir,
		absolute: false,
	})
		.then((entries) => entries.map(compileContract(parsedArgs)))
		.then((promises) => Promise.all(promises));
};
```

<Tabs>
  <TabItem value="apple" label="Apple" default>
    This is an apple 🍎
  </TabItem>
  <TabItem value="orange" label="Orange">
    This is an orange 🍊
  </TabItem>
  <TabItem value="banana" label="Banana">
    This is a banana 🍌
  </TabItem>
</Tabs>
