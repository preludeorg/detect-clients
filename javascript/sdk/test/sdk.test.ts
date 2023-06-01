import { randomUUID } from "crypto";
import { addDays, subDays } from "date-fns";
import { readFileSync, unlinkSync, writeFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RunCodes, Service } from "../lib/main";
import { spawn } from "child_process";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

declare module "vitest" {
  export interface TestContext {
    service: Service;
  }
}

const testEmail =
  process.env.EMAIL ?? "test@auto-accept.developer.preludesecurity.com";
const host = process.env.API_HOST ?? "https://api.us2.preludesecurity.com";

const createAccount = async () => {
  const service = new Service({
    host,
  });
  const creds = await service.iam.newAccount({
    email: testEmail,
    name: "test",
  });
  await sleep(5000);
  return creds;
};

describe("SDK Test", () => {
  let probeName = "nocturnal";

  describe("IAM Controller", () => {
    const service = new Service({
      host,
    });

    beforeAll(async () => {
      const account = await service.iam.newAccount({
        email: testEmail,
        name: "test",
      });
      expect(account).toHaveProperty("account");
      expect(account).toHaveProperty("token");
      await sleep(4000);
      service.setCredentials(account);
    });

    afterAll(async () => {
      await service.iam.purgeAccount();
    });

    it("updateAccount should update the account", async () => {
      const result = await service.iam.updateAccount(1);
      expect(result).to.be.true;
      const account = await service.iam.getAccount();
      expect(account).toHaveProperty("mode");
      expect(account.mode).eq(1);
    });

    it("getAccount should return the account", async () => {
      const account = await service.iam.getAccount();
      expect(account).toHaveProperty("whoami");
      expect(account.whoami).eq(testEmail);
    });

    it("createUser should return an object with a value token that is a UUID4", async () => {
      const result = await service.iam.createUser({
        permission: 3,
        email: "registration",
        name: "registration",
        expires: addDays(new Date(), 1).toISOString(),
      });
      expect(result.token).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
      );
      const account = await service.iam.getAccount();
      expect(account).toHaveProperty("users");
      expect(account.users).toHaveLength(2);
    });

    it("deleteUser should return a boolean true", async () => {
      const result = await service.iam.deleteUser("registration");
      expect(result).to.be.true;
      const account = await service.iam.getAccount();
      expect(account).toHaveProperty("users");
      expect(account.users).to.have.lengthOf(1);
    });
  });

  describe("Build Controller", async () => {
    const testId = randomUUID();
    const testName = "test";
    const templateName = `${testId}.go`;
    const testUnit = "AV";

    const service = new Service({
      host,
    });

    beforeAll(async () => {
      const credentials = await createAccount();
      service.setCredentials(credentials);
    });

    afterAll(async () => {
      await service.iam.purgeAccount();
    });

    it("createTest should not throw an error", async () => {
      await service.build.createTest(testId, testName, testUnit);
    });

    it("upload should have an attachment in the getTest call", async () => {
      const file = readFileSync(`${__dirname}/templates/template.go`, "utf8");
      let data = file.toString();
      data = data.replace("$ID", testId);
      data = data.replace("$NAME", testName);
      data = data.replace("$UNIT", testUnit);
      data = data.replace("$CREATED", new Date().toISOString());
      await service.build.upload(testId, templateName, data);
      const test = await service.detect.getTest(testId);
      expect(test.attachments).toEqual(expect.arrayContaining([templateName]));
    });

    it("deleteTest should not throw an error", async () => {
      await service.build.deleteTest(testId);
    });
  });

  describe("Detect Controller", () => {
    const hostName = "test_host";
    const serial = "test_serial";
    const edrId = "test_edr_id";
    const tags = "test_tag";
    const healthCheck = "39de298a-911d-4a3b-aed4-1e8281010a9a";
    let endpointToken = "";
    let endpointId = "";
    let activeTest = "";
    let start = subDays(new Date(), 7).toISOString();
    let finish = addDays(new Date(), 1).toISOString();
    const testId = randomUUID();
    const testName = "test";
    const templateName = `${testId}.go`;
    const testUnit = "AV";

    const service = new Service({
      host,
    });

    beforeAll(async () => {
      const credentials = await createAccount();
      service.setCredentials(credentials);
    });

    afterAll(async () => {
      await service.iam.purgeAccount();
    });

    it("listAdvisories should return an array greater than 0", async () => {
      const result = await service.detect.listAdvisories();
      expect(result).length > 0;
    });

    it("listTests should return an array with length greater that 1", async () => {
      const result = await service.detect.listTests();
      expect(result).to.have.length.greaterThan(1);
    });

    it("getTest should return a test object", async () => {
      await service.build.createTest(testId, testName, testUnit);
      const test = await service.detect.getTest(testId);
      expect(test).toHaveProperty("attachments");
      expect(test).toHaveProperty("unit");
      activeTest = testId;
    });

    it("download should return the same data as the upload", async () => {
      const file = readFileSync(`${__dirname}/templates/template.go`, "utf8");
      let data = file.toString();
      data = data.replace("$ID", testId);
      data = data.replace("$NAME", testName);
      data = data.replace("$UNIT", testUnit);
      data = data.replace("$CREATED", new Date().toISOString());
      await service.build.upload(testId, templateName, data);
      const download = await service.detect.download(testId, templateName);
      expect(download).toContain(testId);
      expect(download).toContain(testName);
    });

    it("enableTest should add a new test to the queue", async function () {
      await service.detect.enableTest({
        test: activeTest,
        runCode: RunCodes.DEBUG,
        tags: tags,
      });

      const result = (await service.iam.getAccount()).queue;

      expect(result).toHaveLength(2);
      expect(result).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            test: activeTest,
            run_code: RunCodes.DEBUG,
          }),
        ])
      );
    });

    it("registerEndpoint should return a string with length 32", async () => {
      const result = await service.detect.registerEndpoint({
        host: hostName,
        serial_num: serial,
        edr_id: edrId,
        tags,
        endpoint_id: "",
      });
      expect(result).toHaveLength(32);
      endpointToken = result;
    });

    it("listEndpoints should return an array with length 1", async () => {
      const result = await service.detect.listEndpoints();
      expect(result).toHaveLength(1);
      expect(result[0].host).eq(hostName);
      endpointId = result[0].endpoint_id;
    });

    describe("with probe", () => {
      afterAll(async () => {
        unlinkSync(`${probeName}.sh`);
      });

      it("download should return a string", async () => {
        const service = new Service({
          host,
        });
        const result = await service.probe.download({
          name: probeName,
          dos: "linux-arm64",
        });
        expect(result).to.be.a("string");
        writeFileSync(`${probeName}.sh`, result, { mode: 0o755 });
      });

      it(
        "spawns the probe",
        async () => {
          await new Promise((resolve) => {
            const process = spawn(`./${probeName}.sh`, {
              env: {
                PRELUDE_TOKEN: endpointToken,
              },
            });
            let count = 0;
            process.stderr.on("data", (data) => {
              if (data.toString().includes("Completed")) {
                count++;
              }
              if (count === 2) {
                resolve(data);
              }
            });
          });
        },
        { timeout: 30_000 }
      );

      it(
        "describeActivity should return logs for 2 tests",
        async function () {
          await sleep(3000);
          const result = await service.detect.describeActivity({
            start,
            finish,
            view: "logs",
          });
          expect(result).toHaveLength(2);
        },
        { retry: 5 }
      );
    });

    it("socialStats should return an object with a non-empty array of values", async function () {
      const result = await service.detect.socialStats(healthCheck);
      expect(Object.values(result)).to.have.length.greaterThanOrEqual(1);
    });

    it("disableTest should remove the test from the queue", async function () {
      await service.detect.disableTest({
        test: activeTest,
        tags: tags,
      });
      const result = (await service.iam.getAccount()).queue;
      expect(result).toHaveLength(1);
    });

    it("deleteEndpoint should remove the endpoint from the list", async function () {
      await service.detect.deleteEndpoint(endpointId);
      const result = await service.detect.listEndpoints();
      expect(result).to.have.lengthOf(0);
    });
  });
});
