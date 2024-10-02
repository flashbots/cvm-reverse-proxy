module github.com/flashbots/cvm-reverse-proxy

go 1.22.4

replace github.com/martinjungblut/go-cryptsetup => github.com/daniel-weisse/go-cryptsetup v0.0.0-20230705150314-d8c07bd1723c

replace (
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.30.2
	k8s.io/controller-manager => k8s.io/controller-manager v0.30.2
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.30.2
	k8s.io/dynamic-resource-allocation => k8s.io/dynamic-resource-allocation v0.30.2
	k8s.io/endpointslice => k8s.io/endpointslice v0.30.2
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.30.2
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.30.2
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.30.2
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.30.2
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.30.2
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.30.2
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.30.2
)

require (
	cloud.google.com/go/compute v1.27.1
	cloud.google.com/go/compute/metadata v0.5.1
	cloud.google.com/go/kms v1.18.1
	cloud.google.com/go/storage v1.42.0
	github.com/Azure/azure-sdk-for-go v68.0.0+incompatible
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.13.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.7.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6 v6.1.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6 v6.0.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.3.2
	github.com/BurntSushi/toml v1.4.0
	github.com/aws/aws-sdk-go v1.54.9
	github.com/aws/aws-sdk-go-v2 v1.30.0
	github.com/aws/aws-sdk-go-v2/config v1.27.22
	github.com/aws/aws-sdk-go-v2/credentials v1.17.22
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.8
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.17.2
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.38.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.167.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.33.0
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.23.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.57.0
	github.com/aws/smithy-go v1.20.2
	github.com/edgelesssys/constellation/v2 v2.17.0
	github.com/edgelesssys/go-azguestattestation v0.0.0-20240513062303-05f8770a633d
	github.com/edgelesssys/go-tdx-qpl v0.0.0-20240123150912-dcad3c41ec5f
	github.com/go-playground/locales v0.14.1
	github.com/go-playground/universal-translator v0.18.1
	github.com/go-playground/validator/v10 v10.22.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/go-sev-guest v0.11.1
	github.com/google/go-tdx-guest v0.3.1
	github.com/google/go-tpm v0.9.1
	github.com/google/go-tpm-tools v0.4.4
	github.com/google/uuid v1.6.0
	github.com/googleapis/gax-go/v2 v2.12.5
	github.com/gophercloud/gophercloud/v2 v2.1.0
	github.com/gophercloud/utils/v2 v2.0.0-20240812072210-8ce1fc0f2894
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.1.0
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.16
	github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2 v2.0.9
	github.com/hashicorp/go-kms-wrapping/wrappers/azurekeyvault/v2 v2.0.11
	github.com/hashicorp/go-kms-wrapping/wrappers/gcpckms/v2 v2.0.12
	github.com/martinjungblut/go-cryptsetup v0.0.0-20220520180014-fd0874fd07a6
	github.com/mitchellh/go-homedir v1.1.0
	github.com/regclient/regclient v0.7.1
	github.com/schollz/progressbar/v3 v3.14.4
	github.com/secure-systems-lab/go-securesystemslib v0.8.0
	github.com/siderolabs/talos/pkg/machinery v1.7.5
	github.com/sigstore/rekor v1.3.6
	github.com/sigstore/sigstore v1.8.6
	github.com/spf13/afero v1.11.0
	github.com/spf13/cobra v1.8.1
	github.com/stretchr/testify v1.9.0
	github.com/urfave/cli/v2 v2.27.2
	github.com/vincent-petithory/dataurl v1.0.0
	go.uber.org/goleak v1.3.0
	golang.org/x/crypto v0.25.0
	golang.org/x/mod v0.18.0
	golang.org/x/tools v0.22.0
	google.golang.org/api v0.186.0
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.34.2
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.30.3
	k8s.io/apiextensions-apiserver v0.30.3
	k8s.io/apimachinery v0.30.3
	k8s.io/client-go v0.30.3
	k8s.io/kubernetes v1.30.2
	k8s.io/utils v0.0.0-20240502163921-fe8a2dddb1d0
)

require (
	cloud.google.com/go v0.115.0 // indirect
	cloud.google.com/go/auth v0.6.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.2 // indirect
	cloud.google.com/go/iam v1.1.8 // indirect
	cloud.google.com/go/longrunning v0.5.7 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.10.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys v0.10.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/internal v0.7.1 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.29 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.23 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.3.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.17.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.4 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20231217050601-ba74d44ecf5f // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-chi/chi v4.1.2+incompatible // indirect
	github.com/go-jose/go-jose/v3 v3.0.3 // indirect
	github.com/go-jose/go-jose/v4 v4.0.1 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.23.0 // indirect
	github.com/go-openapi/errors v0.22.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/loads v0.22.0 // indirect
	github.com/go-openapi/runtime v0.28.0 // indirect
	github.com/go-openapi/spec v0.21.0 // indirect
	github.com/go-openapi/strfmt v0.23.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-openapi/validate v0.24.0 // indirect
	github.com/gofrs/uuid/v5 v5.3.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/certificate-transparency-go v1.1.8 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/go-attestation v0.5.1 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-containerregistry v0.19.2 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-secure-stdlib/awsutil v0.1.6 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/imdario/mergo v0.3.15 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jedisct1/go-minisign v0.0.0-20230811132847-661be99b8267 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20240620165639-de9c06129bec // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.19.0 // indirect
	github.com/prometheus/client_model v0.6.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sassoftware/relic v7.2.1+incompatible // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/theupdateframework/go-tuf v0.7.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/vtolstov/go-ioctl v0.0.0-20151206205506-6be9cced4810 // indirect
	github.com/xrash/smetrics v0.0.0-20240312152122-5f08fbb34913 // indirect
	go.mongodb.org/mongo-driver v1.14.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.52.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.52.0 // indirect
	go.opentelemetry.io/otel v1.27.0 // indirect
	go.opentelemetry.io/otel/metric v1.27.0 // indirect
	go.opentelemetry.io/otel/trace v1.27.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/oauth2 v0.21.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/term v0.22.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/genproto v0.0.0-20240617180043-68d350f18fd4 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240617180043-68d350f18fd4 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240617180043-68d350f18fd4 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/cluster-bootstrap v0.30.2 // indirect
	k8s.io/component-base v0.30.3 // indirect
	k8s.io/klog/v2 v2.120.1 // indirect
	k8s.io/kube-openapi v0.0.0-20240228011516-70dd3763d340 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)
