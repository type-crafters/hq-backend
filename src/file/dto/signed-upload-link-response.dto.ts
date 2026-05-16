export class SignedUploadLinkResponse {
    public key: string;
    public url: string;

    private constructor(key: string, url: string) {
        this.key = key;
        this.url = url;
    } 

    public static of(key: string, url: string) {
        return new SignedUploadLinkResponse(key, url);
    }
}