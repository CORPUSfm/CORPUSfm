// Every value here can only be read back from the frozen output of the one signing run, so there is
// nothing legitimate to author in advance. While this is null the page makes no release-specific
// claim and offers no download link that could be wrong.
export type ReleaseTrust = {
  version: string;
  releaseUrl: string;
  installerAsset: string;
  signerThumbprint: string;
  certificateAsset: string;
  certificateUrl: string;
  trustRecordAsset: string;
  trustRecordUrl: string;
};

export const releaseTrust: ReleaseTrust | null = null;
