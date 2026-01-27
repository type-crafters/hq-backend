import assert from "assert";

export class ApplicationRepository {
    _documentClient;
    _requiredEnvVars;
    _environment;

    constructor(documentClient) {
        if (new.target === ApplicationRepository) {
            throw new Error("Abstract class 'ApplicationRepository' cannot be instantiated directly.");
        }
        this._documentClient = documentClient;
        this._environment = new Map();
    }
    
    setEnvironment(environment) {
        this._requiredEnvVars.forEach(variable => {
            assert(environment[variable], `Missing required variable '${variable}' in execution environment.`);
            this._environment.set(variable, environment[variable]);
        });
    }

    _checkEnvionment() {
        this._requiredEnvVars.forEach(variable => {
            assert(this._environment.get(variable), `Missing required variable '${variable}' in internal definition.`);
        });
    }
}