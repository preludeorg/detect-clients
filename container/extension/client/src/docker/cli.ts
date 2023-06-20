import { createDockerDesktopClient } from '@docker/extension-api-client';
import {
  DockerDesktopClient,
  ExecOptions,
} from '@docker/extension-api-client-types/dist/v1';
import { DockerContainer, ProbeStatus } from './types';
import {
  Credentials,
  DownloadParams,
  RegisterEndpointParams,
  Service,
} from '@theprelude/sdk';

export default class DockerCli {
  #ddClient: DockerDesktopClient;
  #service: Service;

  constructor() {
    this.#ddClient = createDockerDesktopClient();
    this.#service = new Service({
      host: 'https://api.preludesecurity.com',
    });
  }

  setCredentials(credentials: Credentials) {
    this.#service.setCredentials(credentials);
  }

  getCredentials(): boolean {
    return !!this.#service.credentials;
  }

  async listContainers(): Promise<DockerContainer[]> {
    return (await this.#ddClient.docker.listContainers()) as DockerContainer[];
  }

  async deployProbe(containerId: string): Promise<ProbeStatus> {
    const endpointToken = await this.#registerEndpoint(containerId);
    const probeCode = await this.#downloadProbe();
    const base64ProbeCode = btoa(probeCode);

    await this.#ddClient.docker.cli.exec('exec', [
      containerId,
      '/bin/sh',
      '-c',
      `"echo '${base64ProbeCode}' | base64 -d > /tmp/nocturnal && chmod +x /tmp/nocturnal"`,
    ]);
    await this.#ddClient.docker.cli.exec(
      'exec',
      [containerId, '/bin/sh', '-c', '"/tmp/nocturnal &"'],
      {
        Detach: true,
        Env: ['PRELUDE_TOKEN=' + endpointToken],
      } as ExecOptions,
    );
    return ProbeStatus.Running;
  }

  async checkDependencies(
    containers: DockerContainer[],
  ): Promise<DockerContainer[]> {
    return await Promise.all(
      containers.map(async (container) => {
        container.ProbeStatus = await this.#checkCurl(container.Id);
        if (container.ProbeStatus !== ProbeStatus.Unsupported) {
          container.ProbeStatus = await this.#checkRunningProbe(container.Id);
        }
        return container;
      }),
    );
  }

  async #checkRunningProbe(containerId: string): Promise<ProbeStatus> {
    try {
      await this.#ddClient.docker.cli.exec('exec', [
        containerId,
        '/bin/sh',
        '-c',
        '"ps a --deselect | grep [n]octurnal"',
      ]);
      return ProbeStatus.Running;
    } catch (e) {
      return ProbeStatus.NotInstalled;
    }
  }

  async #checkCurl(containerId: string): Promise<ProbeStatus> {
    try {
      await this.#ddClient.docker.cli.exec('exec', [
        containerId,
        '/bin/sh',
        '-c',
        '"curl --version"',
      ]);
      return ProbeStatus.NotInstalled;
    } catch (e) {
      return ProbeStatus.Unsupported;
    }
  }

  async #registerEndpoint(containerId: string): Promise<string> {
    const params = {
      host: this.#ddClient.host.hostname,
      serial_num: containerId,
    } as RegisterEndpointParams;
    return await this.#service.detect.registerEndpoint(params);
  }

  async #downloadProbe(): Promise<string> {
    const params = {
      name: 'nocturnal',
      dos: 'linux-x86_64',
    } as DownloadParams;
    return await this.#service.probe.download(params);
  }
}
