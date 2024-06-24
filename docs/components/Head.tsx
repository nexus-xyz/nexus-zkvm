import { default as NextHead } from "next/head";

export const Head = () => {
  return (
    <NextHead>
      <link rel="icon" href="/favicon.ico" />

      <title>Nexus Docs</title>
      <meta name="description" content="Enabling Verifiable Computing" />

      <meta property="og:url" content="https://docs.nexus.xyz/" />
      <meta property="og:type" content="website" />
      <meta property="og:title" content="Nexus" />
      <meta property="og:description" content="Enabling Verifiable Computing" />
      <meta
        property="og:image"
        content="https://docs.nexus.xyz/images/opengraph.png"
      />

      <meta name="twitter:card" content="summary_large_image" />
      <meta property="twitter:domain" content="docs.nexus.xyz" />
      <meta property="twitter:url" content="https://docs.nexus.xyz/" />
      <meta name="twitter:title" content="NexusLabsHQ" />
      <meta name="twitter:site" content="@NexusLabsHQ" />
      <meta
        name="twitter:description"
        content="Enabling Verifiable Computing"
      />
      <meta
        name="twitter:image"
        content="https://docs.nexus.xyz/images/opengraph.png"
      />
    </NextHead>
  );
};
