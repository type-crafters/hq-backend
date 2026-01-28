import { RequiresEnvironment } from "../lib/RequiresEnvironment";

export class ApplicationRepository extends RequiresEnvironment {
    documentClient;

    constructor(documentClient) {
        if (new.target === ApplicationRepository) {
            throw new Error("Abstract class 'ApplicationRepository' cannot be instantiated directly.");
        }
        this.documentClient = documentClient;
    }
}