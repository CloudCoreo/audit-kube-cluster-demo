coreo_agent_selector_rule 'check-kubectl' do
    action :define
    timeout 30
    control 'check-kubectl' do
        describe command('kubectl') do
            it { should exist }
        end
    end
end

coreo_agent_selector_rule 'check-docker' do
    action :define
    timeout 30
    control 'check-docker' do
      describe command('docker') do
         it { should exist }
      end
    end
  end

coreo_agent_selector_rule 'check-linux' do
    action :define
    timeout 120
    control 'check-linux' do
        describe os.linux? do
            it { should eq true }
        end
    end
end

coreo_agent_audit_rule 'cis-kubernetes-benchmark-1-1-1' do
    action :define
    link 'http://kb.cloudcoreo.com/'
    display_name 'Ensure that the --allow-privileged argument is set to false'
    description 'Do not allow privileged containers.\n\nRationale: The privileged container has all the system capabilities, and it also lifts all the limitations enforced by the device cgroup controller. In other words, the container can then do almost everything that the host can do. This flag exists to allow special use-cases, like running Docker within Docker and hence should be avoided for production workloads.'
    category 'Security'
    suggested_action 'Edit the /etc/kubernetes/config file on the master node and set the KUBE_ALLOW_PRIV parameter to "--allow-privileged=false"'
    level 'high'
    selectors ['check-kubectl']
    timeout 120
    control 'cis-kubernetes-benchmark-1.1.1' do
        title 'Ensure that the --allow-privileged argument is set to false'
        desc "Do not allow privileged containers.\n\nRationale: The privileged container has all the system capabilities, and it also lifts all the limitations enforced by the device cgroup controller. In other words, the container can then do almost everything that the host can do. This flag exists to allow special use-cases, like running Docker within Docker and hence should be avoided for production workloads."
        impact 1.0
        
        tag cis: 'kubernetes:1.1.1'
        tag level: 1
        
        describe processes('kube-apiserver').commands.to_s do
            it { should match(/--allow-privileged=false/) }
        end
    end
end

coreo_agent_audit_rule 'cis-docker-benchmark-2-1' do
    action :define
    link 'http://kb.cloudcoreo.com/'
    display_name 'Restrict network traffic between containers'
    description 'By default, all network traffic is allowed between containers on the same host. If not desired, restrict all the intercontainer communication. Link specific containers together that require inter communication.'
    category 'Security'
    suggested_action 'Run the docker in daemon mode and pass "--icc=false" as argument.'
    level 'high'
    selectors ['check-docker']
    timeout 120
    control 'cis-docker-benchmark-2.1' do
        impact 1.0
        title 'Restrict network traffic between containers'
        desc 'By default, all network traffic is allowed between containers on the same host. If not desired, restrict all the intercontainer communication. Link specific containers together that require inter communication.'
      
        tag 'daemon'
        tag cis: 'docker:2.1'
        tag level: 1
        ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'
      
        describe json('/etc/docker/daemon.json') do
          its(['icc']) { should eq(false) }
        end
    end
end

coreo_agent_audit_rule 'cis-dil-benchmark-1-5-3' do
    action :define
    link 'http://kb.cloudcoreo.com/'
    display_name 'Ensure address space layout randomization (ASLR) is enabled'
    description 'Address space layout randomization (ASLR) is an exploit mitigation technique which randomly arranges the address space of key data areas of a process.\n\nRationale: Randomly placing virtual memory regions will make it difficult to write memory page exploits as the memory placement will be consistently shifting.'
    category 'Security'
    suggested_action 'Set "kernel.randomize_va_space = 2" in the /etc/sysctl.conf file'
    level 'high'
    selectors ['check-linux']
    timeout 120
    control 'cis-dil-benchmark-1.5.3' do
        title 'Ensure address space layout randomization (ASLR) is enabled'
        desc  "Address space layout randomization (ASLR) is an exploit mitigation technique which randomly arranges the address space of key data areas of a process.\n\nRationale: Randomly placing virtual memory regions will make it difficult to write memory page exploits as the memory placement will be consistently shifting."
        impact 1.0
      
        tag cis: 'distribution-independent-linux:1.5.3'
        tag level: 1
      
        describe kernel_parameter('kernel.randomize_va_space') do
          its(:value) { should eq 2 }
        end
    end
  end

  coreo_agent_rule_runner 'audit-kube-cluster-rules' do
    action :run
    rules ${AUDIT_KUBE_CLUSTER_RULES}
    filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
  end
