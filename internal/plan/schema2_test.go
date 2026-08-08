package plan

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
)

const (
	// otherInfrastructure is a second canonical UUIDv4, used wherever a test
	// needs a value that is well-formed and still not the one under test.
	otherInfrastructure = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3"

	vectorServiceProfile = ServiceProfileBentoPDF
	vectorLocalPort      = 8080
	vectorRouteHost      = "bentopdf.lab.your-cloud.test"
	vectorBackendPort    = 8080

	// The inputs of the private profile's vectors. The origin and the published
	// name are the same string on purpose: that is what the contract describes —
	// the service answers under the exact name the route serves — and a vector
	// that used two names would prove the encoding without proving the shape of
	// the scenario it encodes.
	vectorPrivateProfile   = ServiceProfileVaultwarden
	vectorOriginHost       = "vault.lab.your-cloud.test"
	vectorLinkRouteHost    = "vault.lab.your-cloud.test"
	vectorLinkBackendPort  = 8080
	vectorPrivateLocalPort = 8080
	vectorSnapshotSlot     = "nightly"

	// The six canonical documents of the schema 2 vectors, byte for byte. A
	// transport may reindent them; the Controller emits exactly these bytes.
	vectorWebServicePlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"deploy_web_service",` +
		`"service_profile":"bentopdf","image_reference":"ghcr.io/alam00000/bentopdf",` +
		`"image_digest":"sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0",` +
		`"local_port":8080}`
	vectorWebServiceRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"remove_web_service",` +
		`"service_profile":"bentopdf","image_reference":"ghcr.io/alam00000/bentopdf",` +
		`"image_digest":"sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0",` +
		`"local_port":8080}`
	vectorEntrypointPlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"deploy_entrypoint",` +
		`"image_reference":"docker.io/library/traefik",` +
		`"image_digest":"sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"}`
	vectorEntrypointRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"remove_entrypoint",` +
		`"image_reference":"docker.io/library/traefik",` +
		`"image_digest":"sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"}`
	vectorRoutePlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"publish_route",` +
		`"route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}`
	vectorRouteRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"retire_route",` +
		`"route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}`

	// The six transcripts, byte for byte. The Rust side of this palier, tracked
	// by #89, must reproduce these exact vectors from its own encoder: a
	// canonical encoding that exists in two implementations is only canonical
	// while the two agree byte for byte, and a drift caught here is a drift that
	// never reaches a machine as an approval the other side refuses.
	vectorWebServicePlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000126465706c6f795f7765625f" +
		"736572766963650000000862656e746f7064660000001a676863722e696f2f61" +
		"6c616d30303030302f62656e746f70646600000020a4ed090f29823da5e296e2" +
		"c2f8603664da71676156ea47c3f186cc73eec38db000001f90"
	vectorWebServiceRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000001272656d6f76655f7765625f" +
		"736572766963650000000862656e746f7064660000001a676863722e696f2f61" +
		"6c616d30303030302f62656e746f70646600000020a4ed090f29823da5e296e2" +
		"c2f8603664da71676156ea47c3f186cc73eec38db000001f90"
	vectorEntrypointPlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000116465706c6f795f656e7472" +
		"79706f696e7400000019646f636b65722e696f2f6c6962726172792f74726165" +
		"66696b000000209c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab261" +
		"4cbaf410dcb2ac"
	vectorEntrypointRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000001172656d6f76655f656e7472" +
		"79706f696e7400000019646f636b65722e696f2f6c6962726172792f74726165" +
		"66696b000000209c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab261" +
		"4cbaf410dcb2ac"
	vectorRoutePlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000d7075626c6973685f726f75" +
		"74650000001c62656e746f7064662e6c61622e796f75722d636c6f75642e7465" +
		"737400001f90"
	vectorRouteRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000c7265746972655f726f7574" +
		"650000001c62656e746f7064662e6c61622e796f75722d636c6f75642e746573" +
		"7400001f90"

	// The eight canonical documents of the private profile's vectors, byte for
	// byte, under the same rule.
	//
	// The rollback of the restore is the one document of the product that names
	// the reserved slot. It is pinned here for exactly that reason: it is built,
	// signed, transported and decoded like any other plan, and the Rust side has
	// to produce these bytes rather than a shape of its own.
	vectorPrivateServicePlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"deploy_private_service",` +
		`"service_profile":"vaultwarden","image_reference":"docker.io/vaultwarden/server",` +
		`"image_digest":"sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8",` +
		`"local_port":8080,"origin_host":"vault.lab.your-cloud.test"}`
	vectorPrivateServiceRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"remove_private_service",` +
		`"service_profile":"vaultwarden","image_reference":"docker.io/vaultwarden/server",` +
		`"image_digest":"sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8",` +
		`"local_port":8080,"origin_host":"vault.lab.your-cloud.test"}`
	vectorLinkRoutePlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"publish_link_route",` +
		`"route_host":"vault.lab.your-cloud.test","backend_port":8080}`
	vectorLinkRouteRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"retire_link_route",` +
		`"route_host":"vault.lab.your-cloud.test","backend_port":8080}`
	vectorSnapshotPlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"snapshot_service",` +
		`"service_profile":"vaultwarden","snapshot_slot":"nightly"}`
	vectorSnapshotRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"discard_snapshot",` +
		`"service_profile":"vaultwarden","snapshot_slot":"nightly"}`
	vectorRestorePlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"restore_service",` +
		`"service_profile":"vaultwarden","snapshot_slot":"nightly"}`
	vectorRestoreRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"restore_service",` +
		`"service_profile":"vaultwarden","snapshot_slot":"previous"}`

	// The eight transcripts of the private profile, byte for byte, under the same
	// obligation on the Rust side — tracked for this palier by `#101`.
	vectorPrivateServicePlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000166465706c6f795f70726976" +
		"6174655f736572766963650000000b7661756c7477617264656e0000001c646f" +
		"636b65722e696f2f7661756c7477617264656e2f73657276657200000020ebdf" +
		"e70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e80000" +
		"1f90000000197661756c742e6c61622e796f75722d636c6f75642e74657374"
	vectorPrivateServiceRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000001672656d6f76655f70726976" +
		"6174655f736572766963650000000b7661756c7477617264656e0000001c646f" +
		"636b65722e696f2f7661756c7477617264656e2f73657276657200000020ebdf" +
		"e70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e80000" +
		"1f90000000197661756c742e6c61622e796f75722d636c6f75642e74657374"
	vectorLinkRoutePlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000127075626c6973685f6c696e" +
		"6b5f726f757465000000197661756c742e6c61622e796f75722d636c6f75642e" +
		"7465737400001f90"
	vectorLinkRouteRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000117265746972655f6c696e6b" +
		"5f726f757465000000197661756c742e6c61622e796f75722d636c6f75642e74" +
		"65737400001f90"
	vectorSnapshotPlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d3100000010736e617073686f745f7365" +
		"72766963650000000b7661756c7477617264656e000000076e696768746c79"
	vectorSnapshotRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d3100000010646973636172645f736e61" +
		"7073686f740000000b7661756c7477617264656e000000076e696768746c79"
	vectorRestorePlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000f726573746f72655f736572" +
		"766963650000000b7661756c7477617264656e000000076e696768746c79"
	vectorRestoreRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000f726573746f72655f736572" +
		"766963650000000b7661756c7477617264656e0000000870726576696f7573"

	// The six digests an approval envelope of these vectors names as plan_sha256
	// and rollback_sha256, in the exact spelling that envelope requires.
	vectorWebServicePlanSHA256     = "99f6e6401d74583f64e4200e6e47cd365ab299466eebe1c1a7210f260b0366ae"
	vectorWebServiceRollbackSHA256 = "4e480f76a7247cde6c41990e941512dce70f0a272a17a2618211bd03230ced68"
	vectorEntrypointPlanSHA256     = "fe15d468f77ed9ca6b54da9a63860278894be7db4b6d997898b55fcb602f3722"
	vectorEntrypointRollbackSHA256 = "1b91a7fa77b7d02cc16ce5d694b1709f641a341c849b4459de0ee3960d1cfcd8"
	vectorRoutePlanSHA256          = "3d92c310868a8ba98aca5501c069bd0e4674757f787c8095e7c39d65d8d20a89"
	vectorRouteRollbackSHA256      = "93e844abe96e68f157eb715ace9ff423004b0c64c68536d4e79ebc8206da1324"

	// The eight digests of the private profile, under the same rule.
	vectorPrivateServicePlanSHA256     = "b4d69bc7fcd277a5c165cd9494f2a88cb3ea8acf06f66906a10f831292f03372"
	vectorPrivateServiceRollbackSHA256 = "c1650b0d359671aafc7fc19bc1d0f050bcf561558cfe3a82bfd897c16d0c7ba0"
	vectorLinkRoutePlanSHA256          = "384fe095408f815bcc6d9b0be5655eaadabefe01c1a717bd0ff641567a5f3fbd"
	vectorLinkRouteRollbackSHA256      = "c17842e513bd8af2da8cee699db20c24b59ae00d2fcfddfa0004caad1cc2d1db"
	vectorSnapshotPlanSHA256           = "3de5108f5e7f2934579128bcfa8a09b3a6bbb16739b37f53e61d941261c7c6e3"
	vectorSnapshotRollbackSHA256       = "0bedf38650c70b58a36e8a0a28944dd53bd9720bce77012be2227ffa85192cae"
	vectorRestorePlanSHA256            = "6a6b71a15f969916a426fdfdcefca22ab670935a04459079eb724c18e180aebc"
	vectorRestoreRollbackSHA256        = "1be3be0186ff3be565e6c4df4fc5a864a8a28f1c3929d029b3ec6ecb38c11b5a"

	// The two digests of a route of the public profile carrying exactly the host
	// and the port of the link route vectors above.
	//
	// They exist so that the shared-tail property is pinned rather than merely
	// computed: publish_route and publish_link_route describe two different
	// states with identical field lists and identical values, and these are the
	// bytes that prove the two never hash the same. The Rust side pins them for
	// the same reason.
	vectorSameFieldsRouteSHA256       = "28513b85c3cb68488757f68009171820350d573efc10009eef0d540ffab193cf"
	vectorSameFieldsRetireRouteSHA256 = "cc1300fdc24448cb152cc9dbc42f8c9bcefe1f915012855d30abf8005cb15d57"

	// A real digest of another image of the same registry. It is refused for the
	// same reason the resolved probe digest is: the plan names one pin and
	// nothing may stand in for it.
	otherPinnedDigest = "sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab"

	// The inputs of the third door's two vectors.
	//
	// They pin the two definitions the servicedefinition package pins as its own
	// vectors — the reference one, which interpolates the origin, and the minimal
	// one, which declares no environment at all — so that the slug, the repository
	// and the digest of a plan are held against the very document the other
	// package froze rather than against a second invention. A drift in either
	// package fails on both sides rather than on neither.
	//
	// The two image digests are synthetic and deliberately look it: the third door
	// pins no image, so there is no real digest to name here, and thirty-two bytes
	// counting from one and from thirty-three are values a reader recognises as
	// the test's own rather than mistaking for an identity of the product.
	vectorUserServiceSlug    = "lab-notes"
	vectorUserServiceDigest  = "c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce"
	vectorUserImageReference = "registry.lab.your-cloud.test/your-cloud/lab-notes"
	vectorUserImageDigest    = "sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	vectorUserLocalPort      = 8080
	vectorUserOriginHost     = "notes.lab.your-cloud.test"
	vectorMinimalSlug        = "minimal"
	vectorMinimalDigest      = "faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c"
	vectorMinimalReference   = "registry.lab.your-cloud.test/minimal"
	vectorMinimalImageDigest = "sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	vectorMinimalUserPort    = 8081
	vectorMinimalUserOrigin  = ""

	// The four canonical documents of the third door's vectors, byte for byte,
	// under the same rule as every group before them.
	//
	// The minimal pair renders `"origin_host":""` rather than omitting the field.
	// That is the canonical spelling of a plan whose definition does not consume
	// an origin, and it is pinned here for exactly that reason: a document that
	// left the field out and this one are the same plan with the same digest, and
	// this is the one spelling they both freeze to.
	vectorUserServicePlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"deploy_user_service",` +
		`"definition_slug":"lab-notes",` +
		`"definition_digest":"c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce",` +
		`"image_reference":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
		`"image_digest":"sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",` +
		`"local_port":8080,"origin_host":"notes.lab.your-cloud.test"}`
	vectorUserServiceRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"remove_user_service",` +
		`"definition_slug":"lab-notes",` +
		`"definition_digest":"c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce",` +
		`"image_reference":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
		`"image_digest":"sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",` +
		`"local_port":8080,"origin_host":"notes.lab.your-cloud.test"}`
	vectorMinimalUserPlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"deploy_user_service",` +
		`"definition_slug":"minimal",` +
		`"definition_digest":"faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c",` +
		`"image_reference":"registry.lab.your-cloud.test/minimal",` +
		`"image_digest":"sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",` +
		`"local_port":8081,"origin_host":""}`
	vectorMinimalUserRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"remove_user_service",` +
		`"definition_slug":"minimal",` +
		`"definition_digest":"faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c",` +
		`"image_reference":"registry.lab.your-cloud.test/minimal",` +
		`"image_digest":"sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",` +
		`"local_port":8081,"origin_host":""}`

	// The four transcripts of the third door, byte for byte, under the same
	// obligation on the Rust side, which pins the same vectors from its own
	// encoder in `plan_v2.rs`.
	//
	// The minimal pair closes on `00000000`: the origin is a length-prefixed field
	// of length zero rather than an absence, which is what keeps the end of the
	// tail from depending on a rule the bytes do not carry.
	vectorUserServicePlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000136465706c6f795f75736572" +
		"5f73657276696365000000096c61622d6e6f74657300000020c0f30d7c7f8635" +
		"d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce00000031726567" +
		"69737472792e6c61622e796f75722d636c6f75642e746573742f796f75722d63" +
		"6c6f75642f6c61622d6e6f746573000000200102030405060708090a0b0c0d0e" +
		"0f101112131415161718191a1b1c1d1e1f2000001f90000000196e6f7465732e" +
		"6c61622e796f75722d636c6f75642e74657374"
	vectorUserServiceRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000001372656d6f76655f75736572" +
		"5f73657276696365000000096c61622d6e6f74657300000020c0f30d7c7f8635" +
		"d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce00000031726567" +
		"69737472792e6c61622e796f75722d636c6f75642e746573742f796f75722d63" +
		"6c6f75642f6c61622d6e6f746573000000200102030405060708090a0b0c0d0e" +
		"0f101112131415161718191a1b1c1d1e1f2000001f90000000196e6f7465732e" +
		"6c61622e796f75722d636c6f75642e74657374"
	vectorMinimalUserPlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000136465706c6f795f75736572" +
		"5f73657276696365000000076d696e696d616c00000020faf14b5c09ce831694" +
		"66632fe2d37063453fe924154b6cc265b62fdd6aebd95c000000247265676973" +
		"7472792e6c61622e796f75722d636c6f75642e746573742f6d696e696d616c00" +
		"0000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d" +
		"3e3f4000001f9100000000"
	vectorMinimalUserRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000001372656d6f76655f75736572" +
		"5f73657276696365000000076d696e696d616c00000020faf14b5c09ce831694" +
		"66632fe2d37063453fe924154b6cc265b62fdd6aebd95c000000247265676973" +
		"7472792e6c61622e796f75722d636c6f75642e746573742f6d696e696d616c00" +
		"0000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d" +
		"3e3f4000001f9100000000"

	// The four digests of the third door, under the same rule.
	vectorUserServicePlanSHA256     = "604b9300bb6f321d53759365cc7064fed1fc9b794b8afdbe811a1742d8133a59"
	vectorUserServiceRollbackSHA256 = "b2737aba239eb3d43326c43e1508687b33ade43ed5fd62a97cfe0866b6deabc8"
	vectorMinimalUserPlanSHA256     = "305f7fac725f8c7cd0970cd4db3b92af60a339b1cd1fa569b61858865210a753"
	vectorMinimalUserRollbackSHA256 = "bb76c62b75d4fd70d7437e75d82396c5b9ae6df3ef6a65e881ac20a222bcc5d3"
)

// The two definitions the third door's vectors pin, as the exact canonical bytes
// the servicedefinition package froze them as.
//
// They are spelled here rather than imported as values, because what the two
// packages must agree on is bytes: a definition this package parses out of these
// strings is the definition that package renders out of its own fields, or the
// vectors below stop matching.
const (
	vectorReferenceDefinitionDocument = `{"schema_version":1,"slug":"lab-notes",` +
		`"image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
		`"container_port":8080,"volumes":["/srv/notes","/var/lib/lab-notes"],` +
		`"tmpfs":["/tmp"],"environment":["LAB_NOTES_TITLE=Your Cloud lab notes",` +
		`"LAB_NOTES_ORIGIN=https://{origin_host}/","LAB_NOTES_READ_ONLY=1"],` +
		`"secret_keys":["LAB_NOTES_ADMIN_TOKEN"]}`
	vectorMinimalDefinitionDocument = `{"schema_version":1,"slug":"minimal",` +
		`"image_repository":"registry.lab.your-cloud.test/minimal","container_port":80,` +
		`"volumes":[],"tmpfs":[],"environment":[],"secret_keys":[]}`
)

// vectorReferenceDefinition and vectorMinimalDefinition parse the two documents
// above, so that a builder test names a definition the way the Controller does:
// by handing over the whole frozen document rather than three of its fields.
func vectorReferenceDefinition(t *testing.T) servicedefinition.Document {
	t.Helper()
	return decodedDefinition(t, vectorReferenceDefinitionDocument)
}

func vectorMinimalDefinition(t *testing.T) servicedefinition.Document {
	t.Helper()
	return decodedDefinition(t, vectorMinimalDefinitionDocument)
}

func decodedDefinition(t *testing.T, document string) servicedefinition.Document {
	t.Helper()
	parsed, err := servicedefinition.Decode([]byte(document))
	if err != nil {
		t.Fatalf("the pinned definition is outside its own contract: %v", err)
	}
	return parsed
}

func vectorUserService() UserServiceDocument {
	return UserServiceDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationDeployUserService,
		DefinitionSlug:   vectorUserServiceSlug,
		DefinitionDigest: vectorUserServiceDigest,
		ImageReference:   vectorUserImageReference,
		ImageDigest:      vectorUserImageDigest,
		LocalPort:        vectorUserLocalPort,
		OriginHost:       vectorUserOriginHost,
	}
}

func vectorMinimalUserService() UserServiceDocument {
	return UserServiceDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationDeployUserService,
		DefinitionSlug:   vectorMinimalSlug,
		DefinitionDigest: vectorMinimalDigest,
		ImageReference:   vectorMinimalReference,
		ImageDigest:      vectorMinimalImageDigest,
		LocalPort:        vectorMinimalUserPort,
		OriginHost:       vectorMinimalUserOrigin,
	}
}

func vectorWebService() WebServiceDocument {
	return WebServiceDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationDeployWebService,
		ServiceProfile:   vectorServiceProfile,
		ImageReference:   BentoPDFImageReference,
		ImageDigest:      BentoPDFImageDigest,
		LocalPort:        vectorLocalPort,
	}
}

func vectorEntrypoint() EntrypointDocument {
	return EntrypointDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationDeployEntrypoint,
		ImageReference:   EntrypointImageReference,
		ImageDigest:      EntrypointImageDigest,
	}
}

func vectorRoute() RouteDocument {
	return RouteDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationPublishRoute,
		RouteHost:        vectorRouteHost,
		BackendPort:      vectorBackendPort,
	}
}

func vectorPrivateService() PrivateServiceDocument {
	return PrivateServiceDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationDeployPrivateService,
		ServiceProfile:   vectorPrivateProfile,
		ImageReference:   VaultwardenImageReference,
		ImageDigest:      VaultwardenImageDigest,
		LocalPort:        vectorPrivateLocalPort,
		OriginHost:       vectorOriginHost,
	}
}

func vectorLinkRoute() LinkRouteDocument {
	return LinkRouteDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationPublishLinkRoute,
		RouteHost:        vectorLinkRouteHost,
		BackendPort:      vectorLinkBackendPort,
	}
}

func vectorSnapshot() SnapshotDocument {
	return SnapshotDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationSnapshotService,
		ServiceProfile:   vectorPrivateProfile,
		SnapshotSlot:     vectorSnapshotSlot,
	}
}

func vectorRestore() RestoreDocument {
	return RestoreDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationRestoreService,
		ServiceProfile:   vectorPrivateProfile,
		SnapshotSlot:     vectorSnapshotSlot,
	}
}

// hostilePlanDocument encodes a document without validating it, which is what a
// hostile test needs: the refusal under test must come from the decoder rather
// than from the encoder refusing to produce the bytes in the first place. Both
// the schema 2 and the schema 3 tables render their subjects through it.
func hostilePlanDocument(t *testing.T, document any) []byte {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodedHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// TestDeterministicSchemaTwoVectorsAreHeldWithTheRustSide is the
// interoperability proof of the schema 2 encoding, for each of its operation
// groups.
//
// Every transcript, every digest and every canonical document is pinned here
// literally. The Rust implementation pins the same values from its own encoder —
// #89 for the three groups of the public profile, #101 for the four of the
// private one — so a single byte of drift in either implementation fails here
// rather than producing plans the other side hashes differently on a real
// machine.
func TestDeterministicSchemaTwoVectorsAreHeldWithTheRustSide(t *testing.T) {
	t.Parallel()
	for _, subject := range []struct {
		group              string
		build              func() (V2Pair, error)
		planDocument       string
		rollbackDocument   string
		planTranscript     string
		rollbackTranscript string
		planSHA256         string
		rollbackSHA256     string
		transcriptLength   int
	}{
		{
			group: "web service",
			build: func() (V2Pair, error) {
				return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
					vectorMachine, vectorServiceProfile, vectorLocalPort)
			},
			planDocument:       vectorWebServicePlanDocument,
			rollbackDocument:   vectorWebServiceRollbackDocument,
			planTranscript:     vectorWebServicePlanTranscriptHex,
			rollbackTranscript: vectorWebServiceRollbackTranscriptHex,
			planSHA256:         vectorWebServicePlanSHA256,
			rollbackSHA256:     vectorWebServiceRollbackSHA256,
			transcriptLength:   185,
		},
		{
			group: "entrypoint",
			build: func() (V2Pair, error) {
				return BuildEntrypointPair(OperationDeployEntrypoint, vectorInfrastructure, vectorMachine)
			},
			planDocument:       vectorEntrypointPlanDocument,
			rollbackDocument:   vectorEntrypointRollbackDocument,
			planTranscript:     vectorEntrypointPlanTranscriptHex,
			rollbackTranscript: vectorEntrypointRollbackTranscriptHex,
			planSHA256:         vectorEntrypointPlanSHA256,
			rollbackSHA256:     vectorEntrypointRollbackSHA256,
			transcriptLength:   167,
		},
		{
			group: "route",
			build: func() (V2Pair, error) {
				return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
					vectorMachine, vectorRouteHost, vectorBackendPort)
			},
			planDocument:       vectorRoutePlanDocument,
			rollbackDocument:   vectorRouteRollbackDocument,
			planTranscript:     vectorRoutePlanTranscriptHex,
			rollbackTranscript: vectorRouteRollbackTranscriptHex,
			planSHA256:         vectorRoutePlanSHA256,
			rollbackSHA256:     vectorRouteRollbackSHA256,
			transcriptLength:   134,
		},
		{
			group: "private service",
			build: func() (V2Pair, error) {
				return BuildPrivateServicePair(OperationDeployPrivateService, vectorInfrastructure,
					vectorMachine, vectorPrivateProfile, vectorPrivateLocalPort, vectorOriginHost)
			},
			planDocument:       vectorPrivateServicePlanDocument,
			rollbackDocument:   vectorPrivateServiceRollbackDocument,
			planTranscript:     vectorPrivateServicePlanTranscriptHex,
			rollbackTranscript: vectorPrivateServiceRollbackTranscriptHex,
			planSHA256:         vectorPrivateServicePlanSHA256,
			rollbackSHA256:     vectorPrivateServiceRollbackSHA256,
			transcriptLength:   223,
		},
		{
			group: "link route",
			build: func() (V2Pair, error) {
				return BuildLinkRoutePair(OperationPublishLinkRoute, vectorInfrastructure,
					vectorMachine, vectorLinkRouteHost, vectorLinkBackendPort)
			},
			planDocument:       vectorLinkRoutePlanDocument,
			rollbackDocument:   vectorLinkRouteRollbackDocument,
			planTranscript:     vectorLinkRoutePlanTranscriptHex,
			rollbackTranscript: vectorLinkRouteRollbackTranscriptHex,
			planSHA256:         vectorLinkRoutePlanSHA256,
			rollbackSHA256:     vectorLinkRouteRollbackSHA256,
			transcriptLength:   136,
		},
		{
			group: "snapshot",
			build: func() (V2Pair, error) {
				return BuildSnapshotPair(OperationSnapshotService, vectorInfrastructure,
					vectorMachine, vectorPrivateProfile, vectorSnapshotSlot)
			},
			planDocument:       vectorSnapshotPlanDocument,
			rollbackDocument:   vectorSnapshotRollbackDocument,
			planTranscript:     vectorSnapshotPlanTranscriptHex,
			rollbackTranscript: vectorSnapshotRollbackTranscriptHex,
			planSHA256:         vectorSnapshotPlanSHA256,
			rollbackSHA256:     vectorSnapshotRollbackSHA256,
			transcriptLength:   127,
		},
		{
			// The restore is the one group whose rollback is the same operation on
			// another slot, so its two vectors differ by that slot alone — and the
			// reserved one appears here, in the one document of the product that
			// names it.
			group: "restore",
			build: func() (V2Pair, error) {
				return BuildRestorePair(vectorInfrastructure, vectorMachine,
					vectorPrivateProfile, vectorSnapshotSlot)
			},
			planDocument:       vectorRestorePlanDocument,
			rollbackDocument:   vectorRestoreRollbackDocument,
			planTranscript:     vectorRestorePlanTranscriptHex,
			rollbackTranscript: vectorRestoreRollbackTranscriptHex,
			planSHA256:         vectorRestorePlanSHA256,
			rollbackSHA256:     vectorRestoreRollbackSHA256,
			transcriptLength:   126,
		},
		{
			// The third door, built the way the Controller builds it: the definition
			// whole, and only the instance chosen beside it.
			group: "user service",
			build: func() (V2Pair, error) {
				return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
					vectorMachine, vectorReferenceDefinition(t), vectorUserImageDigest,
					vectorUserLocalPort, vectorUserOriginHost)
			},
			planDocument:       vectorUserServicePlanDocument,
			rollbackDocument:   vectorUserServiceRollbackDocument,
			planTranscript:     vectorUserServicePlanTranscriptHex,
			rollbackTranscript: vectorUserServiceRollbackTranscriptHex,
			planSHA256:         vectorUserServicePlanSHA256,
			rollbackSHA256:     vectorUserServiceRollbackSHA256,
			transcriptLength:   275,
		},
		{
			// The same door over a definition that consumes no origin. Its transcript
			// is forty bytes shorter and closes on a length of zero rather than on
			// nothing, which is the whole of the conditional field's encoding.
			group: "user service without an origin",
			build: func() (V2Pair, error) {
				return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
					vectorMachine, vectorMinimalDefinition(t), vectorMinimalImageDigest,
					vectorMinimalUserPort, vectorMinimalUserOrigin)
			},
			planDocument:       vectorMinimalUserPlanDocument,
			rollbackDocument:   vectorMinimalUserRollbackDocument,
			planTranscript:     vectorMinimalUserPlanTranscriptHex,
			rollbackTranscript: vectorMinimalUserRollbackTranscriptHex,
			planSHA256:         vectorMinimalUserPlanSHA256,
			rollbackSHA256:     vectorMinimalUserRollbackSHA256,
			transcriptLength:   235,
		},
	} {
		pair, err := subject.build()
		if err != nil {
			t.Fatalf("%s: %v", subject.group, err)
		}
		frozen, err := pair.Freeze()
		if err != nil {
			t.Fatalf("%s: %v", subject.group, err)
		}

		transcript, err := pair.Plan.Transcript()
		if err != nil {
			t.Fatalf("%s: %v", subject.group, err)
		}
		if len(transcript) != subject.transcriptLength {
			t.Fatalf("%s plan transcript length drifted: %d", subject.group, len(transcript))
		}
		if !bytes.Equal(transcript, decodedHex(t, subject.planTranscript)) {
			t.Fatalf("%s plan transcript drifted from the shared vector:\n%s",
				subject.group, hex.EncodeToString(transcript))
		}
		if !strings.HasPrefix(string(transcript), TranscriptDomainV2) {
			t.Fatalf("%s plan transcript does not start with its own domain separator", subject.group)
		}

		rollbackTranscript, err := pair.Rollback.Transcript()
		if err != nil {
			t.Fatalf("%s: %v", subject.group, err)
		}
		if !bytes.Equal(rollbackTranscript, decodedHex(t, subject.rollbackTranscript)) {
			t.Fatalf("%s rollback transcript drifted from the shared vector:\n%s",
				subject.group, hex.EncodeToString(rollbackTranscript))
		}

		if string(frozen.PlanDocument) != subject.planDocument {
			t.Fatalf("%s canonical plan document drifted:\n%s", subject.group, frozen.PlanDocument)
		}
		if string(frozen.RollbackDocument) != subject.rollbackDocument {
			t.Fatalf("%s canonical rollback document drifted:\n%s", subject.group, frozen.RollbackDocument)
		}
		if frozen.PlanSHA256 != subject.planSHA256 {
			t.Fatalf("%s plan_sha256 drifted: %s", subject.group, frozen.PlanSHA256)
		}
		if frozen.RollbackSHA256 != subject.rollbackSHA256 {
			t.Fatalf("%s rollback_sha256 drifted: %s", subject.group, frozen.RollbackSHA256)
		}
	}
}

// TestNoTwoSchemaTwoDigestsCollideAcrossOperationGroups is what makes the
// transcript layout unambiguous without a group tag: the six vectors of the
// palier are six distinct documents and six distinct digests, and none of them
// is the schema 1 digest of anything.
func TestNoTwoSchemaTwoDigestsCollideAcrossOperationGroups(t *testing.T) {
	t.Parallel()
	seen := map[string]string{
		vectorPlanSHA256:     "schema 1 probe deployment",
		vectorRollbackSHA256: "schema 1 probe removal",
	}
	for name, digest := range map[string]string{
		"web service deployment":     vectorWebServicePlanSHA256,
		"web service removal":        vectorWebServiceRollbackSHA256,
		"entrypoint deployment":      vectorEntrypointPlanSHA256,
		"entrypoint removal":         vectorEntrypointRollbackSHA256,
		"route publication":          vectorRoutePlanSHA256,
		"route retirement":           vectorRouteRollbackSHA256,
		"private service deployment": vectorPrivateServicePlanSHA256,
		"private service removal":    vectorPrivateServiceRollbackSHA256,
		"link route publication":     vectorLinkRoutePlanSHA256,
		"link route retirement":      vectorLinkRouteRollbackSHA256,
		"snapshot":                   vectorSnapshotPlanSHA256,
		"snapshot discard":           vectorSnapshotRollbackSHA256,
		"restore":                    vectorRestorePlanSHA256,
		"restore of the return slot": vectorRestoreRollbackSHA256,
		// The third door's two pairs. The second of them carries no origin, so it
		// is also what proves that an absent field does not collapse two documents
		// into one digest: the same definition deployed with and without an origin
		// would be two states, and they are two digests.
		"user service deployment":                vectorUserServicePlanSHA256,
		"user service removal":                   vectorUserServiceRollbackSHA256,
		"user service deployment with no origin": vectorMinimalUserPlanSHA256,
		"user service removal with no origin":    vectorMinimalUserRollbackSHA256,
	} {
		if other, collision := seen[digest]; collision {
			t.Fatalf("%s and %s name the same digest", name, other)
		}
		seen[digest] = name
	}
}

// TestTwoOperationsCarryingTheSameFieldsStillCarryTwoDigests is the property the
// transcript layout rests on once two groups have the same tail.
//
// A route of the public profile and a route of the private passage name a host
// and a port and nothing else; a snapshot and a restore name a profile and a slot
// and nothing else. Their tails are byte for byte identical, and the four
// documents are four states: publishing a name to a loopback service is not
// publishing it through the tunnel, and archiving data is not replacing it. What
// keeps their digests apart is the operation string, hashed ahead of the tail at
// a determined offset — so this test builds each couple with identical field
// values and requires the digests to differ.
//
// It is written against the pinned vectors rather than against freshly built
// documents so that a failure names a value a reader can look up.
func TestTwoOperationsCarryingTheSameFieldsStillCarryTwoDigests(t *testing.T) {
	t.Parallel()
	route, err := BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
		vectorMachine, vectorLinkRouteHost, vectorLinkBackendPort)
	if err != nil {
		t.Fatal(err)
	}
	linkRoute, err := BuildLinkRoutePair(OperationPublishLinkRoute, vectorInfrastructure,
		vectorMachine, vectorLinkRouteHost, vectorLinkBackendPort)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := BuildSnapshotPair(OperationSnapshotService, vectorInfrastructure,
		vectorMachine, vectorPrivateProfile, vectorSnapshotSlot)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := BuildRestorePair(vectorInfrastructure, vectorMachine,
		vectorPrivateProfile, vectorSnapshotSlot)
	if err != nil {
		t.Fatal(err)
	}

	for name, couple := range map[string]struct{ left, right V2Document }{
		"a public route and a link route carrying the same host and port": {route.Plan, linkRoute.Plan},
		"their two retirements": {route.Rollback, linkRoute.Rollback},
		"a snapshot and a restore naming the same profile and slot": {snapshot.Plan, restore.Plan},
	} {
		leftTranscript, err := couple.left.Transcript()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rightTranscript, err := couple.right.Transcript()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(leftTranscript) == len(rightTranscript) &&
			bytes.Equal(leftTranscript[len(TranscriptDomainV2):], rightTranscript[len(TranscriptDomainV2):]) {
			t.Fatalf("%s: the two transcripts are the same bytes", name)
		}
		leftDigest, err := couple.left.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rightDigest, err := couple.right.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if leftDigest == rightDigest {
			t.Fatalf("%s: %s and %s share a digest",
				name, couple.left.OperationName(), couple.right.OperationName())
		}
	}

	// The same statement at the level of the pinned vectors, so that a drift in
	// either encoder fails against values a reader can look up rather than
	// against values the test just computed.
	//
	// The two route digests below cover the same host and the same port as the
	// link route vector — that is the whole point of pinning a second route here
	// rather than reusing the public profile's own vector, whose host differs. The
	// snapshot and the restore vectors already carry identical fields, so they are
	// held directly.
	frozenRoute, err := route.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	if frozenRoute.PlanSHA256 != vectorSameFieldsRouteSHA256 ||
		frozenRoute.RollbackSHA256 != vectorSameFieldsRetireRouteSHA256 {
		t.Fatalf("the route vector of the shared-fields proof drifted: %+v", frozenRoute)
	}
	if vectorSameFieldsRouteSHA256 == vectorLinkRoutePlanSHA256 ||
		vectorSameFieldsRetireRouteSHA256 == vectorLinkRouteRollbackSHA256 {
		t.Fatal("the two published names of the palier share a digest")
	}
	if vectorSnapshotPlanSHA256 == vectorRestorePlanSHA256 {
		t.Fatal("archiving and returning share a digest")
	}

	// Rewriting the operation of one of these documents into the other's is not a
	// refusal and must not be: the result is a well-formed document of the other
	// group, describing another state. It is a second plan, and the only thing
	// that makes it one rather than the first plan reworded is that its digest
	// differs — so a transport that rewrote it carries a document no approval
	// names.
	for name, subject := range map[string]struct {
		document string
		from, to string
		digest   string
	}{
		"a route rewritten into a link route": {vectorRoutePlanDocument,
			OperationPublishRoute, OperationPublishLinkRoute, vectorRoutePlanSHA256},
		"a snapshot rewritten into a restore": {vectorSnapshotPlanDocument,
			OperationSnapshotService, OperationRestoreService, vectorSnapshotPlanSHA256},
	} {
		rewritten := strings.Replace(subject.document, `"`+subject.from+`"`, `"`+subject.to+`"`, 1)
		decoded, err := DecodeV2([]byte(rewritten))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if decoded.OperationName() != subject.to {
			t.Fatalf("%s: the rewritten document names %q", name, decoded.OperationName())
		}
		digest, err := decoded.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest == subject.digest {
			t.Fatalf("%s: rewriting the operation left the digest where it was", name)
		}
	}
}

// TestChangingAnySingleFieldChangesTheSchemaTwoDigest is the central property of
// the transcript, held for each operation group.
//
// A field that could move without moving the digest would be a field the
// Controller owns, since the Controller is the only thing between the human who
// approved a plan and the machine that performs it. The wire documents are read
// back at the end so that a field added to a schema and forgotten in its
// transcript fails here.
func TestChangingAnySingleFieldChangesTheSchemaTwoDigest(t *testing.T) {
	t.Parallel()

	webService := map[string]func(*WebServiceDocument){
		"infrastructure_id": func(d *WebServiceDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *WebServiceDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *WebServiceDocument) { d.Operation = OperationRemoveWebService },
		"local_port":        func(d *WebServiceDocument) { d.LocalPort = vectorLocalPort + 1 },
		"schema_version":    func(d *WebServiceDocument) { d.SchemaVersion = SchemaVersion },
		"service_profile":   func(d *WebServiceDocument) { d.ServiceProfile = "bentopdf-simple" },
		"image_reference":   func(d *WebServiceDocument) { d.ImageReference = "ghcr.io/attacker/bentopdf" },
		"image_digest":      func(d *WebServiceDocument) { d.ImageDigest = otherPinnedDigest },
	}
	reference := rawWebServiceTranscript(t, vectorWebService())
	for field, mutate := range webService {
		moved := vectorWebService()
		mutate(&moved)
		if bytes.Equal(rawWebServiceTranscript(t, moved), reference) {
			t.Fatalf("web service %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorWebServicePlanDocument, keysOf(webService))

	entrypoint := map[string]func(*EntrypointDocument){
		"infrastructure_id": func(d *EntrypointDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *EntrypointDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *EntrypointDocument) { d.Operation = OperationRemoveEntrypoint },
		"schema_version":    func(d *EntrypointDocument) { d.SchemaVersion = SchemaVersion },
		"image_reference":   func(d *EntrypointDocument) { d.ImageReference = "ghcr.io/attacker/traefik" },
		"image_digest":      func(d *EntrypointDocument) { d.ImageDigest = otherPinnedDigest },
	}
	entrypointReference := rawEntrypointTranscript(t, vectorEntrypoint())
	for field, mutate := range entrypoint {
		moved := vectorEntrypoint()
		mutate(&moved)
		if bytes.Equal(rawEntrypointTranscript(t, moved), entrypointReference) {
			t.Fatalf("entrypoint %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorEntrypointPlanDocument, keysOf(entrypoint))

	route := map[string]func(*RouteDocument){
		"infrastructure_id": func(d *RouteDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *RouteDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *RouteDocument) { d.Operation = OperationRetireRoute },
		"schema_version":    func(d *RouteDocument) { d.SchemaVersion = SchemaVersion },
		"route_host":        func(d *RouteDocument) { d.RouteHost = "other.lab.your-cloud.test" },
		"backend_port":      func(d *RouteDocument) { d.BackendPort = vectorBackendPort + 1 },
	}
	routeReference := rawRouteTranscript(vectorRoute())
	for field, mutate := range route {
		moved := vectorRoute()
		mutate(&moved)
		if bytes.Equal(rawRouteTranscript(moved), routeReference) {
			t.Fatalf("route %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorRoutePlanDocument, keysOf(route))

	privateService := map[string]func(*PrivateServiceDocument){
		"infrastructure_id": func(d *PrivateServiceDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *PrivateServiceDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *PrivateServiceDocument) { d.Operation = OperationRemovePrivateService },
		"local_port":        func(d *PrivateServiceDocument) { d.LocalPort = vectorPrivateLocalPort + 1 },
		"schema_version":    func(d *PrivateServiceDocument) { d.SchemaVersion = SchemaVersion },
		"service_profile":   func(d *PrivateServiceDocument) { d.ServiceProfile = ServiceProfileBentoPDF },
		"image_reference":   func(d *PrivateServiceDocument) { d.ImageReference = "ghcr.io/attacker/vaultwarden" },
		"image_digest":      func(d *PrivateServiceDocument) { d.ImageDigest = otherPinnedDigest },
		"origin_host":       func(d *PrivateServiceDocument) { d.OriginHost = "other.lab.your-cloud.test" },
	}
	privateReference := rawPrivateServiceTranscript(t, vectorPrivateService())
	for field, mutate := range privateService {
		moved := vectorPrivateService()
		mutate(&moved)
		if bytes.Equal(rawPrivateServiceTranscript(t, moved), privateReference) {
			t.Fatalf("private service %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorPrivateServicePlanDocument, keysOf(privateService))

	linkRoute := map[string]func(*LinkRouteDocument){
		"infrastructure_id": func(d *LinkRouteDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *LinkRouteDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *LinkRouteDocument) { d.Operation = OperationRetireLinkRoute },
		"schema_version":    func(d *LinkRouteDocument) { d.SchemaVersion = SchemaVersion },
		"route_host":        func(d *LinkRouteDocument) { d.RouteHost = "other.lab.your-cloud.test" },
		"backend_port":      func(d *LinkRouteDocument) { d.BackendPort = vectorLinkBackendPort + 1 },
	}
	linkRouteReference := rawLinkRouteTranscript(vectorLinkRoute())
	for field, mutate := range linkRoute {
		moved := vectorLinkRoute()
		mutate(&moved)
		if bytes.Equal(rawLinkRouteTranscript(moved), linkRouteReference) {
			t.Fatalf("link route %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorLinkRoutePlanDocument, keysOf(linkRoute))

	snapshot := map[string]func(*SnapshotDocument){
		"infrastructure_id": func(d *SnapshotDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *SnapshotDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *SnapshotDocument) { d.Operation = OperationDiscardSnapshot },
		"schema_version":    func(d *SnapshotDocument) { d.SchemaVersion = SchemaVersion },
		"service_profile":   func(d *SnapshotDocument) { d.ServiceProfile = ServiceProfileBentoPDF },
		"snapshot_slot":     func(d *SnapshotDocument) { d.SnapshotSlot = "weekly" },
	}
	snapshotReference := rawSnapshotTranscript(vectorSnapshot())
	for field, mutate := range snapshot {
		moved := vectorSnapshot()
		mutate(&moved)
		if bytes.Equal(rawSnapshotTranscript(moved), snapshotReference) {
			t.Fatalf("snapshot %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorSnapshotPlanDocument, keysOf(snapshot))

	restore := map[string]func(*RestoreDocument){
		"infrastructure_id": func(d *RestoreDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *RestoreDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *RestoreDocument) { d.Operation = OperationSnapshotService },
		"schema_version":    func(d *RestoreDocument) { d.SchemaVersion = SchemaVersion },
		"service_profile":   func(d *RestoreDocument) { d.ServiceProfile = ServiceProfileBentoPDF },
		"snapshot_slot":     func(d *RestoreDocument) { d.SnapshotSlot = ReservedSnapshotSlot },
	}
	restoreReference := rawRestoreTranscript(vectorRestore())
	for field, mutate := range restore {
		moved := vectorRestore()
		mutate(&moved)
		if bytes.Equal(rawRestoreTranscript(moved), restoreReference) {
			t.Fatalf("restore %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorRestorePlanDocument, keysOf(restore))

	userService := map[string]func(*UserServiceDocument){
		"infrastructure_id": func(d *UserServiceDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *UserServiceDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *UserServiceDocument) { d.Operation = OperationRemoveUserService },
		"local_port":        func(d *UserServiceDocument) { d.LocalPort = vectorUserLocalPort + 1 },
		"schema_version":    func(d *UserServiceDocument) { d.SchemaVersion = SchemaVersion },
		"definition_slug":   func(d *UserServiceDocument) { d.DefinitionSlug = vectorMinimalSlug },
		"definition_digest": func(d *UserServiceDocument) { d.DefinitionDigest = vectorMinimalDigest },
		"image_reference":   func(d *UserServiceDocument) { d.ImageReference = "ghcr.io/attacker/lab-notes" },
		"image_digest":      func(d *UserServiceDocument) { d.ImageDigest = otherPinnedDigest },
		"origin_host":       func(d *UserServiceDocument) { d.OriginHost = "other.lab.your-cloud.test" },
	}
	userReference := rawUserServiceTranscript(t, vectorUserService())
	for field, mutate := range userService {
		moved := vectorUserService()
		mutate(&moved)
		if bytes.Equal(rawUserServiceTranscript(t, moved), userReference) {
			t.Fatalf("user service %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorUserServicePlanDocument, keysOf(userService))

	// Removing the origin altogether is the mutation this group has and no other
	// does, and it must move the digest as much as changing it does: a service
	// deployed under a name and the same service deployed under none are two
	// states, so they can never be one set of hashed bytes.
	withoutOrigin := vectorUserService()
	withoutOrigin.OriginHost = ""
	if bytes.Equal(rawUserServiceTranscript(t, withoutOrigin), userReference) {
		t.Fatal("dropping the origin of a user service left the hashed bytes where they were")
	}
	// And the same in the other direction, from the vector that carries none, so
	// that the empty field is proven to be written rather than skipped.
	minimalReference := rawUserServiceTranscript(t, vectorMinimalUserService())
	withOrigin := vectorMinimalUserService()
	withOrigin.OriginHost = vectorUserOriginHost
	if bytes.Equal(rawUserServiceTranscript(t, withOrigin), minimalReference) {
		t.Fatal("adding an origin to a user service left the hashed bytes where they were")
	}
	requireEveryWireFieldIsHeld(t, vectorMinimalUserPlanDocument, keysOf(userService))
}

// The raw transcripts below rebuild the layout for documents Validate refuses,
// so that a pinned field can still be proven to be inside the hashed bytes.

func rawWebServiceTranscript(t *testing.T, document WebServiceDocument) []byte {
	t.Helper()
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ServiceProfile))
	transcript = appendField(transcript, []byte(document.ImageReference))
	transcript = appendField(transcript, decodedHex(t, strings.TrimPrefix(document.ImageDigest, "sha256:")))
	return appendUint32(transcript, uint32(document.LocalPort))
}

func rawEntrypointTranscript(t *testing.T, document EntrypointDocument) []byte {
	t.Helper()
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ImageReference))
	return appendField(transcript, decodedHex(t, strings.TrimPrefix(document.ImageDigest, "sha256:")))
}

func rawRouteTranscript(document RouteDocument) []byte {
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.RouteHost))
	return appendUint32(transcript, uint32(document.BackendPort))
}

func rawPrivateServiceTranscript(t *testing.T, document PrivateServiceDocument) []byte {
	t.Helper()
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ServiceProfile))
	transcript = appendField(transcript, []byte(document.ImageReference))
	transcript = appendField(transcript, decodedHex(t, strings.TrimPrefix(document.ImageDigest, "sha256:")))
	transcript = appendUint32(transcript, uint32(document.LocalPort))
	return appendField(transcript, []byte(document.OriginHost))
}

func rawLinkRouteTranscript(document LinkRouteDocument) []byte {
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.RouteHost))
	return appendUint32(transcript, uint32(document.BackendPort))
}

func rawSnapshotTranscript(document SnapshotDocument) []byte {
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ServiceProfile))
	return appendField(transcript, []byte(document.SnapshotSlot))
}

func rawRestoreTranscript(document RestoreDocument) []byte {
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ServiceProfile))
	return appendField(transcript, []byte(document.SnapshotSlot))
}

func rawUserServiceTranscript(t *testing.T, document UserServiceDocument) []byte {
	t.Helper()
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.DefinitionSlug))
	transcript = appendField(transcript, decodedHex(t, document.DefinitionDigest))
	transcript = appendField(transcript, []byte(document.ImageReference))
	transcript = appendField(transcript, decodedHex(t, strings.TrimPrefix(document.ImageDigest, "sha256:")))
	transcript = appendUint32(transcript, uint32(document.LocalPort))
	return appendField(transcript, []byte(document.OriginHost))
}

func keysOf[V any](table map[string]V) map[string]struct{} {
	names := make(map[string]struct{}, len(table))
	for name := range table {
		names[name] = struct{}{}
	}
	return names
}

func requireEveryWireFieldIsHeld(t *testing.T, document string, held map[string]struct{}) {
	t.Helper()
	wire := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(document), &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire) != len(held) {
		t.Fatalf("the closed field list of this document holds %d fields, not %d", len(held), len(wire))
	}
	for name := range wire {
		if _, bounded := held[name]; !bounded {
			t.Fatalf("field %q of the plan is never held against its digest", name)
		}
	}
}

// TestDecodeV2RefusesEveryWebServiceDocumentOutsideTheContract is the hostile
// table of the service group.
func TestDecodeV2RefusesEveryWebServiceDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV2([]byte(vectorWebServicePlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV2([]byte(vectorWebServiceRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}

	for name, mutate := range map[string]func(*WebServiceDocument){
		"schema 1 version":     func(d *WebServiceDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":        func(d *WebServiceDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":      func(d *WebServiceDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"empty infrastructure": func(d *WebServiceDocument) { d.InfrastructureID = "" },
		"traversal machine":    func(d *WebServiceDocument) { d.MachineID = "../../etc/shadow" },
		"upper-case machine":   func(d *WebServiceDocument) { d.MachineID = "LAB-MACHINE-1" },
		"unknown operation":    func(d *WebServiceDocument) { d.Operation = "install_container" },
		"probe operation":      func(d *WebServiceDocument) { d.Operation = OperationDeployOCIProbe },
		"entrypoint operation": func(d *WebServiceDocument) { d.Operation = OperationDeployEntrypoint },
		"route operation":      func(d *WebServiceDocument) { d.Operation = OperationPublishRoute },
		"empty operation":      func(d *WebServiceDocument) { d.Operation = "" },
		"unknown profile":      func(d *WebServiceDocument) { d.ServiceProfile = "bentopdf-simple" },
		"upper-case profile":   func(d *WebServiceDocument) { d.ServiceProfile = "BentoPDF" },
		"empty profile":        func(d *WebServiceDocument) { d.ServiceProfile = "" },
		// The data-bearing profile at the stateless door, alone and with its own
		// image. It is refused for the reason the private door refuses the
		// stateless profile: a service whose data outlives its container has no
		// business being described by a sheet that declares no volume.
		"the private profile": func(d *WebServiceDocument) { d.ServiceProfile = ServiceProfileVaultwarden },
		"the private profile and its image": func(d *WebServiceDocument) {
			d.ServiceProfile = ServiceProfileVaultwarden
			d.ImageReference = VaultwardenImageReference
			d.ImageDigest = VaultwardenImageDigest
		},
		"private operation":    func(d *WebServiceDocument) { d.Operation = OperationDeployPrivateService },
		"other registry":       func(d *WebServiceDocument) { d.ImageReference = "docker.io/alam00000/bentopdf" },
		"other repository":     func(d *WebServiceDocument) { d.ImageReference = "ghcr.io/attacker/bentopdf" },
		"registry-less":        func(d *WebServiceDocument) { d.ImageReference = "alam00000/bentopdf" },
		"tagged reference":     func(d *WebServiceDocument) { d.ImageReference = BentoPDFImageReference + ":latest" },
		"entrypoint reference": func(d *WebServiceDocument) { d.ImageReference = EntrypointImageReference },
		"entrypoint digest":    func(d *WebServiceDocument) { d.ImageDigest = EntrypointImageDigest },
		"probe digest":         func(d *WebServiceDocument) { d.ImageDigest = otherPinnedDigest },
		"upper-case digest":    func(d *WebServiceDocument) { d.ImageDigest = strings.ToUpper(BentoPDFImageDigest) },
		"other algorithm": func(d *WebServiceDocument) {
			d.ImageDigest = "sha512:" + strings.TrimPrefix(BentoPDFImageDigest, "sha256:")
		},
		"short digest":          func(d *WebServiceDocument) { d.ImageDigest = "sha256:a4ed" },
		"port below range":      func(d *WebServiceDocument) { d.LocalPort = MinLocalPort - 1 },
		"privileged port":       func(d *WebServiceDocument) { d.LocalPort = 443 },
		"absent port":           func(d *WebServiceDocument) { d.LocalPort = 0 },
		"negative port":         func(d *WebServiceDocument) { d.LocalPort = -1 },
		"port above range":      func(d *WebServiceDocument) { d.LocalPort = MaxLocalPort + 1 },
		"port beyond int16":     func(d *WebServiceDocument) { d.LocalPort = 70000 },
		"reference with digest": func(d *WebServiceDocument) { d.ImageReference = BentoPDFImageReference + "@" + BentoPDFImageDigest },
	} {
		document := vectorWebService()
		mutate(&document)
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeV2RefusesEveryEntrypointDocumentOutsideTheContract is the hostile
// table of the entrypoint group. The entrypoint has the shortest field list of
// the palier, so most of its surface is what it must refuse to carry.
func TestDecodeV2RefusesEveryEntrypointDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV2([]byte(vectorEntrypointPlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV2([]byte(vectorEntrypointRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}

	for name, mutate := range map[string]func(*EntrypointDocument){
		"schema 1 version":   func(d *EntrypointDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":      func(d *EntrypointDocument) { d.SchemaVersion = 0 },
		"non version 4 UUID": func(d *EntrypointDocument) { d.InfrastructureID = "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2" },
		"too short machine":  func(d *EntrypointDocument) { d.MachineID = "ab" },
		"unknown operation":  func(d *EntrypointDocument) { d.Operation = "install_container" },
		"service operation":  func(d *EntrypointDocument) { d.Operation = OperationDeployWebService },
		"route operation":    func(d *EntrypointDocument) { d.Operation = OperationRetireRoute },
		"empty operation":    func(d *EntrypointDocument) { d.Operation = "" },
		"service reference":  func(d *EntrypointDocument) { d.ImageReference = BentoPDFImageReference },
		"service digest":     func(d *EntrypointDocument) { d.ImageDigest = BentoPDFImageDigest },
		"probe digest":       func(d *EntrypointDocument) { d.ImageDigest = otherPinnedDigest },
		"tagged reference":   func(d *EntrypointDocument) { d.ImageReference = EntrypointImageReference + ":latest" },
		"registry-less":      func(d *EntrypointDocument) { d.ImageReference = "library/traefik" },
		"unprefixed digest":  func(d *EntrypointDocument) { d.ImageDigest = strings.TrimPrefix(EntrypointImageDigest, "sha256:") },
		"upper-case algorithm": func(d *EntrypointDocument) {
			d.ImageDigest = "SHA256:" + strings.TrimPrefix(EntrypointImageDigest, "sha256:")
		},
	} {
		document := vectorEntrypoint()
		mutate(&document)
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeV2RefusesEveryRouteDocumentOutsideTheContract is the hostile table
// of the route group, and the whole surface of route_host.
//
// A host outside these bounds never reaches a fragment of the entrypoint, which
// is why the bound is here and not in whatever writes the fragment.
func TestDecodeV2RefusesEveryRouteDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV2([]byte(vectorRoutePlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV2([]byte(vectorRouteRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}

	// The bounds themselves are accepted, so that the refusals below name a
	// malformation rather than an off-by-one.
	for name, host := range map[string]string{
		"shortest accepted name": "abc",
		"longest accepted name":  strings.Repeat("a", 248) + ".test",
		"punycode label":         "xn--bcher-kva.lab.your-cloud.test",
		"digits only":            "127.0.0.1",
	} {
		document := vectorRoute()
		document.RouteHost = host
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
	}
	for _, port := range []int{MinBackendPort, MaxBackendPort} {
		document := vectorRoute()
		document.BackendPort = port
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err != nil {
			t.Fatalf("the bound %d of the backend range was refused: %v", port, err)
		}
	}

	for name, mutate := range map[string]func(*RouteDocument){
		"schema 1 version":     func(d *RouteDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":        func(d *RouteDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":      func(d *RouteDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"machine on hyphen":    func(d *RouteDocument) { d.MachineID = "-lab-machine-1" },
		"unknown operation":    func(d *RouteDocument) { d.Operation = "publish_ingress" },
		"service operation":    func(d *RouteDocument) { d.Operation = OperationRemoveWebService },
		"entrypoint operation": func(d *RouteDocument) { d.Operation = OperationRemoveEntrypoint },
		"empty operation":      func(d *RouteDocument) { d.Operation = "" },

		"empty host":            func(d *RouteDocument) { d.RouteHost = "" },
		"host below bound":      func(d *RouteDocument) { d.RouteHost = "ab" },
		"host above bound":      func(d *RouteDocument) { d.RouteHost = strings.Repeat("a", 249) + ".test" },
		"wildcard host":         func(d *RouteDocument) { d.RouteHost = "*.lab.your-cloud.test" },
		"bare wildcard":         func(d *RouteDocument) { d.RouteHost = "*" },
		"upper-case host":       func(d *RouteDocument) { d.RouteHost = "BentoPDF.lab.your-cloud.test" },
		"leading dot":           func(d *RouteDocument) { d.RouteHost = ".lab.your-cloud.test" },
		"trailing dot":          func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test." },
		"leading hyphen":        func(d *RouteDocument) { d.RouteHost = "-bentopdf.lab.your-cloud.test" },
		"trailing hyphen":       func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test-" },
		"consecutive dots":      func(d *RouteDocument) { d.RouteHost = "bentopdf..lab.your-cloud.test" },
		"empty label at start":  func(d *RouteDocument) { d.RouteHost = "..test" },
		"underscore host":       func(d *RouteDocument) { d.RouteHost = "bento_pdf.lab.your-cloud.test" },
		"host carrying a port":  func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test:443" },
		"host carrying a path":  func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test/pdf" },
		"host carrying a rule":  func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.test`)||Host(`evil.test" },
		"host carrying a space": func(d *RouteDocument) { d.RouteHost = "bentopdf lab.your-cloud.test" },
		"host carrying a break": func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.test\nevil.test" },
		"non ASCII host":        func(d *RouteDocument) { d.RouteHost = "bücher.lab.your-cloud.test" },
		"trailing NUL host":     func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test\x00" },

		"backend below range":  func(d *RouteDocument) { d.BackendPort = MinBackendPort - 1 },
		"privileged backend":   func(d *RouteDocument) { d.BackendPort = 443 },
		"absent backend":       func(d *RouteDocument) { d.BackendPort = 0 },
		"negative backend":     func(d *RouteDocument) { d.BackendPort = -1 },
		"backend above range":  func(d *RouteDocument) { d.BackendPort = MaxBackendPort + 1 },
		"backend beyond int16": func(d *RouteDocument) { d.BackendPort = 70000 },
	} {
		document := vectorRoute()
		mutate(&document)
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeV2RefusesEveryPrivateServiceDocumentOutsideTheContract is the
// hostile table of the private service group.
//
// The two rows that matter most are the profile ones, and they run in both
// directions here and in the stateless table above: a data-bearing service does
// not pass through the stateless door, and a stateless service does not pass
// through the private one. Everything else is the surface origin_host adds.
func TestDecodeV2RefusesEveryPrivateServiceDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV2([]byte(vectorPrivateServicePlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV2([]byte(vectorPrivateServiceRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}

	for name, mutate := range map[string]func(*PrivateServiceDocument){
		"schema 1 version":     func(d *PrivateServiceDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":        func(d *PrivateServiceDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":      func(d *PrivateServiceDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"empty infrastructure": func(d *PrivateServiceDocument) { d.InfrastructureID = "" },
		"traversal machine":    func(d *PrivateServiceDocument) { d.MachineID = "../../etc/shadow" },
		"unknown operation":    func(d *PrivateServiceDocument) { d.Operation = "install_container" },
		"stateless operation":  func(d *PrivateServiceDocument) { d.Operation = OperationDeployWebService },
		"snapshot operation":   func(d *PrivateServiceDocument) { d.Operation = OperationSnapshotService },
		"link route operation": func(d *PrivateServiceDocument) { d.Operation = OperationPublishLinkRoute },
		"empty operation":      func(d *PrivateServiceDocument) { d.Operation = "" },

		// The stateless profile at the private door, in the exact spelling the
		// other palier pins. It is refused as an unknown name is refused, and
		// before its image is compared.
		"the stateless profile": func(d *PrivateServiceDocument) { d.ServiceProfile = ServiceProfileBentoPDF },
		"the stateless profile and its image": func(d *PrivateServiceDocument) {
			d.ServiceProfile = ServiceProfileBentoPDF
			d.ImageReference = BentoPDFImageReference
			d.ImageDigest = BentoPDFImageDigest
		},
		"unknown profile":    func(d *PrivateServiceDocument) { d.ServiceProfile = "vaultwarden-lite" },
		"upper-case profile": func(d *PrivateServiceDocument) { d.ServiceProfile = "Vaultwarden" },
		"empty profile":      func(d *PrivateServiceDocument) { d.ServiceProfile = "" },

		"other registry":       func(d *PrivateServiceDocument) { d.ImageReference = "ghcr.io/vaultwarden/server" },
		"other repository":     func(d *PrivateServiceDocument) { d.ImageReference = "docker.io/attacker/server" },
		"registry-less":        func(d *PrivateServiceDocument) { d.ImageReference = "vaultwarden/server" },
		"tagged reference":     func(d *PrivateServiceDocument) { d.ImageReference = VaultwardenImageReference + ":1.37.1" },
		"entrypoint reference": func(d *PrivateServiceDocument) { d.ImageReference = EntrypointImageReference },
		"resolved amd64 digest": func(d *PrivateServiceDocument) {
			d.ImageDigest = "sha256:e9efdf001bf0d68c21f2cbfb8e1d9b5961a7ca9c85e0a7e58bf51a13b997d744"
		},
		"stateless digest":  func(d *PrivateServiceDocument) { d.ImageDigest = BentoPDFImageDigest },
		"upper-case digest": func(d *PrivateServiceDocument) { d.ImageDigest = strings.ToUpper(VaultwardenImageDigest) },
		"short digest":      func(d *PrivateServiceDocument) { d.ImageDigest = "sha256:ebdf" },
		"reference with digest": func(d *PrivateServiceDocument) {
			d.ImageReference = VaultwardenImageReference + "@" + VaultwardenImageDigest
		},

		"privileged port":  func(d *PrivateServiceDocument) { d.LocalPort = 443 },
		"absent port":      func(d *PrivateServiceDocument) { d.LocalPort = 0 },
		"negative port":    func(d *PrivateServiceDocument) { d.LocalPort = -1 },
		"port above range": func(d *PrivateServiceDocument) { d.LocalPort = MaxLocalPort + 1 },

		// The whole corpus of the host bound, applied to the field that reuses it.
		"empty origin":            func(d *PrivateServiceDocument) { d.OriginHost = "" },
		"origin below bound":      func(d *PrivateServiceDocument) { d.OriginHost = "ab" },
		"origin above bound":      func(d *PrivateServiceDocument) { d.OriginHost = strings.Repeat("a", 249) + ".test" },
		"wildcard origin":         func(d *PrivateServiceDocument) { d.OriginHost = "*.lab.your-cloud.test" },
		"upper-case origin":       func(d *PrivateServiceDocument) { d.OriginHost = "Vault.lab.your-cloud.test" },
		"origin carrying scheme":  func(d *PrivateServiceDocument) { d.OriginHost = "https://vault.lab.your-cloud.test" },
		"origin carrying a port":  func(d *PrivateServiceDocument) { d.OriginHost = "vault.lab.your-cloud.test:443" },
		"origin carrying a path":  func(d *PrivateServiceDocument) { d.OriginHost = "vault.lab.your-cloud.test/admin" },
		"origin carrying a space": func(d *PrivateServiceDocument) { d.OriginHost = "vault lab.your-cloud.test" },
		"origin carrying a break": func(d *PrivateServiceDocument) { d.OriginHost = "vault.lab.test\nevil.test" },
		"origin on a hyphen":      func(d *PrivateServiceDocument) { d.OriginHost = "-vault.lab.your-cloud.test" },
		"origin on a dot":         func(d *PrivateServiceDocument) { d.OriginHost = ".lab.your-cloud.test" },
		"origin with empty label": func(d *PrivateServiceDocument) { d.OriginHost = "vault..lab.your-cloud.test" },
		"non ASCII origin":        func(d *PrivateServiceDocument) { d.OriginHost = "coffre.lab.your-cloud.tëst" },
		"trailing NUL origin":     func(d *PrivateServiceDocument) { d.OriginHost = "vault.lab.your-cloud.test\x00" },
	} {
		document := vectorPrivateService()
		mutate(&document)
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeV2RefusesEveryLinkRouteDocumentOutsideTheContract is the hostile
// table of the link route group.
//
// It carries the fields of a route of the public profile, so what is proven here
// is that it carries the bounds too: a name this decoder would refuse on one
// operation is not accepted because the traffic behind it takes the tunnel.
func TestDecodeV2RefusesEveryLinkRouteDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV2([]byte(vectorLinkRoutePlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV2([]byte(vectorLinkRouteRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}
	for _, port := range []int{MinBackendPort, MaxBackendPort} {
		document := vectorLinkRoute()
		document.BackendPort = port
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err != nil {
			t.Fatalf("the bound %d of the backend range was refused: %v", port, err)
		}
	}

	for name, mutate := range map[string]func(*LinkRouteDocument){
		"schema 1 version":     func(d *LinkRouteDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":        func(d *LinkRouteDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":      func(d *LinkRouteDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"machine on hyphen":    func(d *LinkRouteDocument) { d.MachineID = "-lab-machine-1" },
		"unknown operation":    func(d *LinkRouteDocument) { d.Operation = "publish_tunnel" },
		"entrypoint operation": func(d *LinkRouteDocument) { d.Operation = OperationRemoveEntrypoint },
		"private operation":    func(d *LinkRouteDocument) { d.Operation = OperationDeployPrivateService },
		"snapshot operation":   func(d *LinkRouteDocument) { d.Operation = OperationSnapshotService },
		"empty operation":      func(d *LinkRouteDocument) { d.Operation = "" },

		"empty host":            func(d *LinkRouteDocument) { d.RouteHost = "" },
		"host below bound":      func(d *LinkRouteDocument) { d.RouteHost = "ab" },
		"host above bound":      func(d *LinkRouteDocument) { d.RouteHost = strings.Repeat("a", 249) + ".test" },
		"wildcard host":         func(d *LinkRouteDocument) { d.RouteHost = "*.lab.your-cloud.test" },
		"upper-case host":       func(d *LinkRouteDocument) { d.RouteHost = "Vault.lab.your-cloud.test" },
		"trailing dot":          func(d *LinkRouteDocument) { d.RouteHost = "vault.lab.your-cloud.test." },
		"consecutive dots":      func(d *LinkRouteDocument) { d.RouteHost = "vault..lab.your-cloud.test" },
		"host carrying a rule":  func(d *LinkRouteDocument) { d.RouteHost = "vault.lab.test`)||Host(`evil.test" },
		"host carrying a port":  func(d *LinkRouteDocument) { d.RouteHost = "vault.lab.your-cloud.test:443" },
		"host carrying a break": func(d *LinkRouteDocument) { d.RouteHost = "vault.lab.test\nevil.test" },

		"backend below range":  func(d *LinkRouteDocument) { d.BackendPort = MinBackendPort - 1 },
		"privileged backend":   func(d *LinkRouteDocument) { d.BackendPort = 443 },
		"absent backend":       func(d *LinkRouteDocument) { d.BackendPort = 0 },
		"negative backend":     func(d *LinkRouteDocument) { d.BackendPort = -1 },
		"backend above range":  func(d *LinkRouteDocument) { d.BackendPort = MaxBackendPort + 1 },
		"backend beyond int16": func(d *LinkRouteDocument) { d.BackendPort = 70000 },
	} {
		document := vectorLinkRoute()
		mutate(&document)
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeV2RefusesEverySnapshotAndRestoreOutsideTheContract is the hostile
// table of the two archive groups, and the whole surface of snapshot_slot.
//
// The reserved slot appears on both sides of this table on purpose: a snapshot
// or a discard naming it is refused, because that slot belongs to the return
// mechanism and a plan that wrote over it or destroyed it would remove the
// possibility of returning; a restore naming it decodes, because that is exactly
// what the signed rollback of a restore is. The asymmetry is the contract, and it
// is stated here rather than left to be inferred.
//
// service_profile is the one field of this schema two doors share, and the table
// holds both readings: the delivered profile the closed list names, and the slug
// of a user definition. What keeps the two unambiguous is the reservation of the
// four names the product owns — so `bentopdf` is refused here as a profile that
// archives nothing and as a slug no definition may take, by one lookup that fails
// rather than by two rules.
func TestDecodeV2RefusesEverySnapshotAndRestoreOutsideTheContract(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"a snapshot":                     vectorSnapshotPlanDocument,
		"a discard":                      vectorSnapshotRollbackDocument,
		"a restore":                      vectorRestorePlanDocument,
		"a restore of the reserved slot": vectorRestoreRollbackDocument,
	} {
		if _, err := DecodeV2([]byte(document)); err != nil {
			t.Fatalf("%s must decode: %v", name, err)
		}
	}

	// A definition's slug is a name these three operations now accept, because
	// the third door shares this field with the delivered profiles. What is
	// accepted is a well-formed name and nothing more: whether a service by that
	// name was ever deployed, and whether its definition declares a volume at all,
	// are facts of a machine that this package reads nowhere.
	for name, profile := range map[string]string{
		"the reference definition": vectorUserServiceSlug,
		"a shortest slug":          "a",
		"a longest slug":           strings.Repeat("a", 16),
	} {
		for _, operation := range []string{OperationSnapshotService, OperationDiscardSnapshot} {
			document := vectorSnapshot()
			document.Operation = operation
			document.ServiceProfile = profile
			if _, err := DecodeV2(hostilePlanDocument(t, document)); err != nil {
				t.Fatalf("a %s of %s was refused: %v", operation, name, err)
			}
		}
		document := vectorRestore()
		document.ServiceProfile = profile
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err != nil {
			t.Fatalf("a restore of %s was refused: %v", name, err)
		}
	}

	// The bounds themselves are accepted, so that the refusals below name a
	// malformation rather than an off-by-one.
	for name, slot := range map[string]string{
		"shortest accepted slot": "a",
		"a single digit":         "0",
		"longest accepted slot":  strings.Repeat("a", MaxSnapshotSlotBytes),
		"hyphenated slot":        "before-upgrade-2026",
		"trailing hyphen":        "nightly-",
	} {
		document := vectorSnapshot()
		document.SnapshotSlot = slot
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
	}

	malformedSlots := map[string]string{
		"empty slot":             "",
		"upper-case slot":        "Nightly",
		"leading hyphen":         "-nightly",
		"one character too long": strings.Repeat("a", MaxSnapshotSlotBytes+1),
		"dotted slot":            "nightly.tar.gz",
		"traversal slot":         "../../etc/shadow",
		"absolute slot":          "/var/lib/your-cloud-svc-vaultwarden",
		"parent slot":            "..",
		"single dot":             ".",
		"slot carrying a slash":  "nightly/latest",
		"underscore slot":        "nightly_2",
		"slot with a space":      "nightly copy",
		"slot with a NUL":        "nightly\x00",
		"slot with a break":      "nightly\nweekly",
		"non ASCII slot":         "sauvegardé",
	}

	for name, mutate := range map[string]func(*SnapshotDocument){
		"schema 1 version":          func(d *SnapshotDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":             func(d *SnapshotDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":           func(d *SnapshotDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"traversal machine":         func(d *SnapshotDocument) { d.MachineID = "../../etc/shadow" },
		"unknown operation":         func(d *SnapshotDocument) { d.Operation = "archive_service" },
		"deploy operation":          func(d *SnapshotDocument) { d.Operation = OperationDeployPrivateService },
		"link route operation":      func(d *SnapshotDocument) { d.Operation = OperationPublishLinkRoute },
		"empty operation":           func(d *SnapshotDocument) { d.Operation = "" },
		"the stateless profile":     func(d *SnapshotDocument) { d.ServiceProfile = ServiceProfileBentoPDF },
		"the probe's reserved name": func(d *SnapshotDocument) { d.ServiceProfile = "probe" },
		"the entry's reserved name": func(d *SnapshotDocument) { d.ServiceProfile = "entrypoint" },
		"a name no slug could be":   func(d *SnapshotDocument) { d.ServiceProfile = "vaultwarden-lite-2" },
		"an upper-case name":        func(d *SnapshotDocument) { d.ServiceProfile = "Vaultwarden" },
		"a dotted name":             func(d *SnapshotDocument) { d.ServiceProfile = "vault.warden" },
		"a traversal name":          func(d *SnapshotDocument) { d.ServiceProfile = "../../etc" },
		"empty profile":             func(d *SnapshotDocument) { d.ServiceProfile = "" },
		"the reserved slot":         func(d *SnapshotDocument) { d.SnapshotSlot = ReservedSnapshotSlot },
	} {
		document := vectorSnapshot()
		mutate(&document)
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("a snapshot naming %s was accepted", name)
		}
		discard := vectorSnapshot()
		discard.Operation = OperationDiscardSnapshot
		mutate(&discard)
		if _, err := DecodeV2(hostilePlanDocument(t, discard)); err == nil {
			t.Fatalf("a discard naming %s was accepted", name)
		}
	}
	for name, slot := range malformedSlots {
		document := vectorSnapshot()
		document.SnapshotSlot = slot
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("a snapshot naming %s was accepted", name)
		}
	}

	for name, mutate := range map[string]func(*RestoreDocument){
		"schema 1 version":          func(d *RestoreDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":             func(d *RestoreDocument) { d.SchemaVersion = 0 },
		"non version 4 UUID":        func(d *RestoreDocument) { d.InfrastructureID = "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2" },
		"too short machine":         func(d *RestoreDocument) { d.MachineID = "ab" },
		"unknown operation":         func(d *RestoreDocument) { d.Operation = "rollback_service" },
		"deploy operation":          func(d *RestoreDocument) { d.Operation = OperationDeployPrivateService },
		"public route":              func(d *RestoreDocument) { d.Operation = OperationPublishRoute },
		"empty operation":           func(d *RestoreDocument) { d.Operation = "" },
		"the stateless profile":     func(d *RestoreDocument) { d.ServiceProfile = ServiceProfileBentoPDF },
		"the probe's reserved name": func(d *RestoreDocument) { d.ServiceProfile = "probe" },
		"a name no slug could be":   func(d *RestoreDocument) { d.ServiceProfile = "vaultwarden-lite-2" },
		"an upper-case name":        func(d *RestoreDocument) { d.ServiceProfile = "Vaultwarden" },
		"empty profile":             func(d *RestoreDocument) { d.ServiceProfile = "" },
	} {
		document := vectorRestore()
		mutate(&document)
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("a restore naming %s was accepted", name)
		}
	}
	for name, slot := range malformedSlots {
		document := vectorRestore()
		document.SnapshotSlot = slot
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("a restore naming %s was accepted", name)
		}
	}
}

// TestDecodeV2RefusesEveryUserServiceDocumentOutsideTheContract is the hostile
// table of the third door.
//
// Three of its fields name a definition this package never reads, so what is
// proven here is exactly what a document can be held to alone: the slug grammar
// the definition package owns — reserved names and all — the one spelling of a
// revision's digest, and the repository rule that refuses a tag on this side too.
// The origin is the one field accepted in two forms, and both are exercised: the
// rule that decides between them needs the definition, and lives beside this
// table in TestAUserServicePlanIsHeldAgainstTheDefinitionItPins.
func TestDecodeV2RefusesEveryUserServiceDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"a deployment":                vectorUserServicePlanDocument,
		"a removal":                   vectorUserServiceRollbackDocument,
		"a deployment with no origin": vectorMinimalUserPlanDocument,
		"a removal with no origin":    vectorMinimalUserRollbackDocument,
	} {
		if _, err := DecodeV2([]byte(document)); err != nil {
			t.Fatalf("%s must decode: %v", name, err)
		}
	}

	// A document that leaves the empty origin out entirely is the same plan under
	// the same digest, and re-encoding it returns the one canonical spelling. That
	// is the whole latitude a transport has over the conditional field.
	omitted := strings.Replace(vectorMinimalUserPlanDocument, `,"origin_host":""`, "", 1)
	decoded, err := DecodeV2([]byte(omitted))
	if err != nil {
		t.Fatalf("a document omitting an empty origin was refused: %v", err)
	}
	digest, err := decoded.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if digest != vectorMinimalUserPlanSHA256 {
		t.Fatalf("omitting an empty origin changed the plan digest: %s", digest)
	}
	reencoded, err := decoded.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(reencoded) != vectorMinimalUserPlanDocument {
		t.Fatalf("an omitted origin did not return to its canonical spelling:\n%s", reencoded)
	}

	for _, port := range []int{MinLocalPort, MaxLocalPort} {
		document := vectorUserService()
		document.LocalPort = port
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err != nil {
			t.Fatalf("the bound %d of the port range was refused: %v", port, err)
		}
	}

	for name, mutate := range map[string]func(*UserServiceDocument){
		"schema 1 version":    func(d *UserServiceDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":       func(d *UserServiceDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":     func(d *UserServiceDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"traversal machine":   func(d *UserServiceDocument) { d.MachineID = "../../etc/shadow" },
		"unknown operation":   func(d *UserServiceDocument) { d.Operation = "start_user_service" },
		"private operation":   func(d *UserServiceDocument) { d.Operation = OperationDeployPrivateService },
		"stateless operation": func(d *UserServiceDocument) { d.Operation = OperationDeployWebService },
		"snapshot operation":  func(d *UserServiceDocument) { d.Operation = OperationSnapshotService },
		"empty operation":     func(d *UserServiceDocument) { d.Operation = "" },

		// The four reserved names are the whole of what keeps one name designating
		// one door, and a plan may not spell them here any more than a definition
		// may take them.
		"the stateless profile as a slug": func(d *UserServiceDocument) { d.DefinitionSlug = ServiceProfileBentoPDF },
		"the private profile as a slug":   func(d *UserServiceDocument) { d.DefinitionSlug = ServiceProfileVaultwarden },
		"the probe's reserved name":       func(d *UserServiceDocument) { d.DefinitionSlug = "probe" },
		"the entry's reserved name":       func(d *UserServiceDocument) { d.DefinitionSlug = "entrypoint" },
		"an empty slug":                   func(d *UserServiceDocument) { d.DefinitionSlug = "" },
		"an upper-case slug":              func(d *UserServiceDocument) { d.DefinitionSlug = "Lab-Notes" },
		"a slug one character too long":   func(d *UserServiceDocument) { d.DefinitionSlug = strings.Repeat("a", 17) },
		"a dotted slug":                   func(d *UserServiceDocument) { d.DefinitionSlug = "lab.notes" },
		"a traversal slug":                func(d *UserServiceDocument) { d.DefinitionSlug = "../../etc" },
		"a slug opening on a hyphen":      func(d *UserServiceDocument) { d.DefinitionSlug = "-lab-notes" },

		"an empty definition digest":     func(d *UserServiceDocument) { d.DefinitionDigest = "" },
		"an upper-case digest":           func(d *UserServiceDocument) { d.DefinitionDigest = strings.ToUpper(vectorUserServiceDigest) },
		"a truncated digest":             func(d *UserServiceDocument) { d.DefinitionDigest = vectorUserServiceDigest[:63] },
		"a digest spelled as an OCI one": func(d *UserServiceDocument) { d.DefinitionDigest = "sha256:" + vectorUserServiceDigest },
		"a non hexadecimal digest":       func(d *UserServiceDocument) { d.DefinitionDigest = strings.Repeat("z", 64) },

		"an empty repository":         func(d *UserServiceDocument) { d.ImageReference = "" },
		"a repository carrying a tag": func(d *UserServiceDocument) { d.ImageReference = vectorUserImageReference + ":latest" },
		"a repository carrying a digest": func(d *UserServiceDocument) {
			d.ImageReference = vectorUserImageReference + "@" + vectorUserImageDigest
		},
		"a repository with no registry": func(d *UserServiceDocument) { d.ImageReference = "lab-notes" },
		"an upper-case repository":      func(d *UserServiceDocument) { d.ImageReference = "registry.lab.your-cloud.test/Lab-Notes" },

		"an empty image digest":    func(d *UserServiceDocument) { d.ImageDigest = "" },
		"a bare image digest":      func(d *UserServiceDocument) { d.ImageDigest = strings.Repeat("a", 64) },
		"an upper-case image":      func(d *UserServiceDocument) { d.ImageDigest = "sha256:" + strings.Repeat("A", 64) },
		"another digest algorithm": func(d *UserServiceDocument) { d.ImageDigest = "sha512:" + strings.Repeat("a", 64) },
		"a truncated image digest": func(d *UserServiceDocument) { d.ImageDigest = "sha256:" + strings.Repeat("a", 63) },

		"a privileged port":   func(d *UserServiceDocument) { d.LocalPort = 443 },
		"an absent port":      func(d *UserServiceDocument) { d.LocalPort = 0 },
		"a negative port":     func(d *UserServiceDocument) { d.LocalPort = -1 },
		"a port above range":  func(d *UserServiceDocument) { d.LocalPort = MaxLocalPort + 1 },
		"a port beyond int16": func(d *UserServiceDocument) { d.LocalPort = 70000 },

		"a wildcard origin":             func(d *UserServiceDocument) { d.OriginHost = "*.lab.your-cloud.test" },
		"an upper-case origin":          func(d *UserServiceDocument) { d.OriginHost = "Notes.lab.your-cloud.test" },
		"an origin with a trailing dot": func(d *UserServiceDocument) { d.OriginHost = "notes.lab.your-cloud.test." },
		"an origin with empty labels":   func(d *UserServiceDocument) { d.OriginHost = "notes..lab.your-cloud.test" },
		"an origin carrying a port":     func(d *UserServiceDocument) { d.OriginHost = "notes.lab.your-cloud.test:443" },
		"an origin carrying a rule":     func(d *UserServiceDocument) { d.OriginHost = "notes.lab.test`)||Host(`evil.test" },
		"an origin carrying a break":    func(d *UserServiceDocument) { d.OriginHost = "notes.lab.test\nevil.test" },
	} {
		document := vectorUserService()
		mutate(&document)
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("a user service naming %s was accepted", name)
		}
		removal := vectorUserService()
		removal.Operation = OperationRemoveUserService
		mutate(&removal)
		if _, err := DecodeV2(hostilePlanDocument(t, removal)); err == nil {
			t.Fatalf("a user service removal naming %s was accepted", name)
		}
	}
}

// TestAUserServicePlanIsHeldAgainstTheDefinitionItPins is the cross-check the
// contract names, and the one rule of this door a document cannot carry alone.
//
// Validating a plan reads one document; agreeing with a definition reads two. The
// second act is held at construction by the Controller, which has the frozen
// definition in hand, and again by the Auxiliary, which receives the definition's
// bytes beside the signed pair and trusts neither the transport nor the
// Controller. Both call this one function, so the two cannot come to disagree —
// and this test is what says so before either of them exists.
func TestAUserServicePlanIsHeldAgainstTheDefinitionItPins(t *testing.T) {
	t.Parallel()
	reference := vectorReferenceDefinition(t)
	minimal := vectorMinimalDefinition(t)

	if !reference.InterpolatesOriginHost() {
		t.Fatal("the reference definition must consume the origin, or this test proves nothing")
	}
	if minimal.InterpolatesOriginHost() {
		t.Fatal("the minimal definition must consume no origin, or this test proves nothing")
	}
	if err := RequireDefinitionAgreement(vectorUserService(), reference); err != nil {
		t.Fatalf("the nominal plan does not agree with the definition it pins: %v", err)
	}
	if err := RequireDefinitionAgreement(vectorMinimalUserService(), minimal); err != nil {
		t.Fatalf("the nominal plan without an origin was refused: %v", err)
	}

	for name, subject := range map[string]struct {
		document   UserServiceDocument
		definition servicedefinition.Document
	}{
		// A digest that names another revision is the refusal the whole door rests
		// on: a plan displaying one document and pinning another would let a human
		// approve bytes they never read.
		"a plan pinning another revision": {
			document: func() UserServiceDocument {
				document := vectorUserService()
				document.DefinitionDigest = vectorMinimalDigest
				return document
			}(),
			definition: reference,
		},
		"a definition that is not the one pinned": {
			document:   vectorUserService(),
			definition: minimal,
		},
		"a plan filed under another slug": {
			document: func() UserServiceDocument {
				document := vectorUserService()
				document.DefinitionSlug = "notes"
				return document
			}(),
			definition: reference,
		},
		// The repository is the definition's, and a plan naming another one is a
		// plan whose image comes from somewhere the human never approved.
		"a plan naming another repository": {
			document: func() UserServiceDocument {
				document := vectorUserService()
				document.ImageReference = "ghcr.io/attacker/lab-notes"
				return document
			}(),
			definition: reference,
		},
		"a plan without the origin its definition interpolates": {
			document: func() UserServiceDocument {
				document := vectorUserService()
				document.OriginHost = ""
				return document
			}(),
			definition: reference,
		},
		"a plan carrying an origin its definition consumes nowhere": {
			document: func() UserServiceDocument {
				document := vectorMinimalUserService()
				document.OriginHost = vectorUserOriginHost
				return document
			}(),
			definition: minimal,
		},
		// Agreement never stands in for validation: a document outside the contract
		// is refused here too, rather than accepted because it matches a definition.
		"a plan outside its own contract": {
			document: func() UserServiceDocument {
				document := vectorUserService()
				document.LocalPort = 443
				return document
			}(),
			definition: reference,
		},
		"a definition outside its own contract": {
			document:   vectorUserService(),
			definition: servicedefinition.Document{},
		},
	} {
		if err := RequireDefinitionAgreement(subject.document, subject.definition); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	// A revision that changes one byte changes the digest, so a plan built against
	// the old revision no longer agrees with the new one. That is what makes
	// "each instance shows the exact revision it runs" a property rather than a
	// hope.
	revised := reference
	revised.ContainerPort++
	if err := RequireDefinitionAgreement(vectorUserService(), revised); err == nil {
		t.Fatal("a plan agreed with a revision it does not pin")
	}
}

// TestTheThreeDoorsRefuseOneAnotherInEveryDirection is the closure the contract
// asks for by name: a definition passes through no door of the delivered
// profiles, and a delivered profile passes through no door of the definitions.
//
// The refusal is a lookup that fails rather than a comparison anyone had to
// write, and it is the reservation of the four names at the source that makes it
// so. This test walks it in both directions so that a table changed on one side
// alone fails here rather than on a machine.
func TestTheThreeDoorsRefuseOneAnotherInEveryDirection(t *testing.T) {
	t.Parallel()
	for _, slug := range []string{vectorUserServiceSlug, vectorMinimalSlug, "blog"} {
		if _, err := BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
			vectorMachine, slug, vectorLocalPort); err == nil {
			t.Fatalf("the stateless door built a plan for the definition %q", slug)
		}
		if _, err := BuildPrivateServicePair(OperationDeployPrivateService, vectorInfrastructure,
			vectorMachine, slug, vectorPrivateLocalPort, vectorOriginHost); err == nil {
			t.Fatalf("the private door built a plan for the definition %q", slug)
		}
	}
	for _, profile := range []string{ServiceProfileBentoPDF, ServiceProfileVaultwarden} {
		document := vectorUserService()
		document.DefinitionSlug = profile
		if _, err := DecodeV2(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("the third door accepted a plan naming the delivered profile %q", profile)
		}
		// And the builder cannot even be asked: a definition may not take one of
		// those names, so no frozen definition can carry it.
		if err := servicedefinition.ValidateSlug(profile); err == nil {
			t.Fatalf("a definition may be written under the delivered profile %q", profile)
		}
	}
}

// TestEverySchemaTwoOperationDecodesIntoItsOwnShape is the exhaustive dispatch of
// this schema, held against the closed table rather than against a list a reader
// has to keep in step with it.
//
// An operation added to operationGroups without a canonical document here fails
// on the count; one added without a decoding case falls through DecodeV2's own
// refusal; and one whose case builds the wrong shape fails on the assertion. The
// three failures are the three ways a closed registry can be left half-extended.
func TestEverySchemaTwoOperationDecodesIntoItsOwnShape(t *testing.T) {
	t.Parallel()
	documents := map[string]struct {
		document string
		shape    V2Document
	}{
		OperationDeployWebService:     {vectorWebServicePlanDocument, WebServiceDocument{}},
		OperationRemoveWebService:     {vectorWebServiceRollbackDocument, WebServiceDocument{}},
		OperationDeployEntrypoint:     {vectorEntrypointPlanDocument, EntrypointDocument{}},
		OperationRemoveEntrypoint:     {vectorEntrypointRollbackDocument, EntrypointDocument{}},
		OperationPublishRoute:         {vectorRoutePlanDocument, RouteDocument{}},
		OperationRetireRoute:          {vectorRouteRollbackDocument, RouteDocument{}},
		OperationDeployPrivateService: {vectorPrivateServicePlanDocument, PrivateServiceDocument{}},
		OperationRemovePrivateService: {vectorPrivateServiceRollbackDocument, PrivateServiceDocument{}},
		OperationPublishLinkRoute:     {vectorLinkRoutePlanDocument, LinkRouteDocument{}},
		OperationRetireLinkRoute:      {vectorLinkRouteRollbackDocument, LinkRouteDocument{}},
		OperationSnapshotService:      {vectorSnapshotPlanDocument, SnapshotDocument{}},
		OperationDiscardSnapshot:      {vectorSnapshotRollbackDocument, SnapshotDocument{}},
		OperationRestoreService:       {vectorRestorePlanDocument, RestoreDocument{}},
		OperationDeployUserService:    {vectorUserServicePlanDocument, UserServiceDocument{}},
		OperationRemoveUserService:    {vectorUserServiceRollbackDocument, UserServiceDocument{}},
	}
	if len(documents) != len(operationGroups) {
		t.Fatalf("this table covers %d operations and the schema describes %d",
			len(documents), len(operationGroups))
	}
	for operation := range operationGroups {
		subject, covered := documents[operation]
		if !covered {
			t.Fatalf("operation %q has no canonical document in this table", operation)
		}
		decoded, err := DecodeV2([]byte(subject.document))
		if err != nil {
			t.Fatalf("operation %q does not decode: %v", operation, err)
		}
		if decoded.OperationName() != operation {
			t.Fatalf("the document of %q decoded as %q", operation, decoded.OperationName())
		}
		if fmt.Sprintf("%T", decoded) != fmt.Sprintf("%T", subject.shape) {
			t.Fatalf("operation %q decoded into %T rather than %T", operation, decoded, subject.shape)
		}
	}
}

// TestNoSchemaTwoDocumentBorrowsAFieldOfAnotherOperation is what the
// discriminator exists for.
//
// The operation is read first, and the document is then held against exactly the
// closed field list that operation declares. A field belonging to another
// operation is an unknown field of the claimed schema, refused before its value
// is read — the strongest form the refusal can take, since it does not depend on
// understanding what was smuggled in.
func TestNoSchemaTwoDocumentBorrowsAFieldOfAnotherOperation(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"a service plan carrying a route host":   withExtraField(vectorWebServicePlanDocument, `"route_host":"evil.test"`),
		"a service plan carrying a backend port": withExtraField(vectorWebServicePlanDocument, `"backend_port":9090`),
		"an entrypoint plan carrying a port":     withExtraField(vectorEntrypointPlanDocument, `"local_port":8080`),
		"an entrypoint plan carrying a host":     withExtraField(vectorEntrypointPlanDocument, `"route_host":"evil.test"`),
		"an entrypoint plan carrying a profile":  withExtraField(vectorEntrypointPlanDocument, `"service_profile":"bentopdf"`),
		"a route plan carrying an image digest":  withExtraField(vectorRoutePlanDocument, `"image_digest":"`+BentoPDFImageDigest+`"`),
		"a route plan carrying an image":         withExtraField(vectorRoutePlanDocument, `"image_reference":"`+BentoPDFImageReference+`"`),
		"a route plan carrying a profile":        withExtraField(vectorRoutePlanDocument, `"service_profile":"bentopdf"`),
		"a route plan carrying a local port":     withExtraField(vectorRoutePlanDocument, `"local_port":8080`),
		"a service plan claiming a route":        strings.Replace(vectorWebServicePlanDocument, `"deploy_web_service"`, `"publish_route"`, 1),
		"a route plan claiming a service":        strings.Replace(vectorRoutePlanDocument, `"publish_route"`, `"deploy_web_service"`, 1),
		"an entrypoint plan claiming a service":  strings.Replace(vectorEntrypointPlanDocument, `"deploy_entrypoint"`, `"deploy_web_service"`, 1),
		"a service plan claiming an entrypoint":  strings.Replace(vectorWebServicePlanDocument, `"deploy_web_service"`, `"deploy_entrypoint"`, 1),
		"a service plan without its profile":     strings.Replace(vectorWebServicePlanDocument, `"service_profile":"bentopdf",`, "", 1),
		"a service plan without its port":        strings.Replace(vectorWebServicePlanDocument, `,"local_port":8080`, "", 1),
		"a route plan without its host":          strings.Replace(vectorRoutePlanDocument, `"route_host":"bentopdf.lab.your-cloud.test",`, "", 1),
		"an entrypoint plan without its image":   strings.Replace(vectorEntrypointPlanDocument, `"image_reference":"docker.io/library/traefik",`, "", 1),
		"a schema 1 probe plan":                  vectorPlanDocument,
		"a schema 2 document with no operation":  strings.Replace(vectorRoutePlanDocument, `"operation":"publish_route",`, "", 1),
		"a schema 2 document naming a number":    strings.Replace(vectorRoutePlanDocument, `"operation":"publish_route"`, `"operation":2`, 1),
		"a schema 2 document naming null":        strings.Replace(vectorRoutePlanDocument, `"operation":"publish_route"`, `"operation":null`, 1),
		"a schema 2 document naming an object":   strings.Replace(vectorRoutePlanDocument, `"operation":"publish_route"`, `"operation":{"name":"publish_route"}`, 1),
		"a document repeating its operation":     withExtraField(vectorRoutePlanDocument, `"operation":"retire_route"`),
		"a document repeating a bounded field":   withExtraField(vectorRoutePlanDocument, `"backend_port":9090`),
		"a document with a non-canonical name":   strings.Replace(vectorRoutePlanDocument, `"route_host"`, `"Route_Host"`, 1),
		"a document with a camel-case name":      strings.Replace(vectorRoutePlanDocument, `"backend_port"`, `"backendPort"`, 1),
		"a document with a stringified port":     strings.Replace(vectorRoutePlanDocument, `"backend_port":8080`, `"backend_port":"8080"`, 1),
		"a document with a fractional port":      strings.Replace(vectorRoutePlanDocument, `"backend_port":8080`, `"backend_port":8080.5`, 1),
		"a document with an exponent port":       strings.Replace(vectorRoutePlanDocument, `"backend_port":8080`, `"backend_port":8.08e3`, 1),
		"a document carrying a command":          withExtraField(vectorWebServicePlanDocument, `"command":"/bin/sh"`),
		"a document carrying a volume":           withExtraField(vectorWebServicePlanDocument, `"volumes":["/etc:/etc"]`),
		"a document carrying a privilege":        withExtraField(vectorEntrypointPlanDocument, `"privileged":true`),
		"a document carrying a tag":              withExtraField(vectorEntrypointPlanDocument, `"tag":"latest"`),
		"a document carrying middleware headers": withExtraField(vectorRoutePlanDocument, `"headers":{"X-Forwarded-For":"1.2.3.4"}`),
		"a document carrying a TLS certificate":  withExtraField(vectorRoutePlanDocument, `"tls_certificate":"-----BEGIN CERTIFICATE-----"`),
		// Two couples of groups carry the same tail, and swapping the operation
		// between them is the one substitution that produces another valid
		// document rather than a refusal — it is another plan, describing another
		// state, under another digest, which is what the shared-tail test holds.
		// What may not cross is a field: the operation selects the shape before any
		// field is read, and the shape then refuses everything the other group
		// carries. The reserved slot is refused the moment the operation that names
		// it stops being the return.
		"a restore of the reserved slot as a discard":  strings.Replace(vectorRestoreRollbackDocument, `"restore_service"`, `"discard_snapshot"`, 1),
		"a restore of the reserved slot as a snapshot": strings.Replace(vectorRestoreRollbackDocument, `"restore_service"`, `"snapshot_service"`, 1),
		"a link route carrying a profile":              withExtraField(vectorLinkRoutePlanDocument, `"service_profile":"vaultwarden"`),
		"a link route carrying a local port":           withExtraField(vectorLinkRoutePlanDocument, `"local_port":8080`),
		"a link route carrying a peer address":         withExtraField(vectorLinkRoutePlanDocument, `"backend_address":"10.66.66.2"`),
		"a private service carrying a route host":      withExtraField(vectorPrivateServicePlanDocument, `"route_host":"evil.test"`),
		"a private service carrying a volume":          withExtraField(vectorPrivateServicePlanDocument, `"volume":"/etc"`),
		"a private service carrying environment":       withExtraField(vectorPrivateServicePlanDocument, `"environment":["SIGNUPS_ALLOWED=true"]`),
		"a private service carrying a slot":            withExtraField(vectorPrivateServicePlanDocument, `"snapshot_slot":"nightly"`),
		"a private service without its origin":         strings.Replace(vectorPrivateServicePlanDocument, `,"origin_host":"vault.lab.your-cloud.test"`, "", 1),
		"a snapshot carrying an image":                 withExtraField(vectorSnapshotPlanDocument, `"image_reference":"`+VaultwardenImageReference+`"`),
		"a snapshot carrying an archive path":          withExtraField(vectorSnapshotPlanDocument, `"archive_path":"/tmp/out.tar.gz"`),
		"a snapshot carrying a digest":                 withExtraField(vectorSnapshotPlanDocument, `"archive_sha256":"`+strings.Repeat("a", 64)+`"`),
		"a snapshot without its slot":                  strings.Replace(vectorSnapshotPlanDocument, `,"snapshot_slot":"nightly"`, "", 1),
		"a restore carrying a second slot":             withExtraField(vectorRestorePlanDocument, `"snapshot_slot":"previous"`),
		"a restore carrying a local port":              withExtraField(vectorRestorePlanDocument, `"local_port":8080`),

		// The third door names a definition where the two others name a profile,
		// so a field of either vocabulary crossing into the other is the whole of
		// what this group has to refuse — and it is refused as an unknown field of
		// the shape the operation selected, before its value is read.
		"a user service carrying a profile":      withExtraField(vectorUserServicePlanDocument, `"service_profile":"vaultwarden"`),
		"a user service carrying a slot":         withExtraField(vectorUserServicePlanDocument, `"snapshot_slot":"nightly"`),
		"a user service carrying a route host":   withExtraField(vectorUserServicePlanDocument, `"route_host":"evil.test"`),
		"a user service carrying a volume":       withExtraField(vectorUserServicePlanDocument, `"volumes":["/srv/notes"]`),
		"a user service carrying environment":    withExtraField(vectorUserServicePlanDocument, `"environment":["LAB_NOTES_TITLE=x"]`),
		"a user service carrying a secret":       withExtraField(vectorUserServicePlanDocument, `"secrets":{"LAB_NOTES_ADMIN_TOKEN":"hunter2"}`),
		"a user service carrying a host path":    withExtraField(vectorUserServicePlanDocument, `"home":"/var/lib/your-cloud-user-lab-notes"`),
		"a user service carrying an account":     withExtraField(vectorUserServicePlanDocument, `"account":"root"`),
		"a user service carrying the definition": withExtraField(vectorUserServicePlanDocument, `"definition_document":"{}"`),
		"a user service repeating its origin":    withExtraField(vectorUserServicePlanDocument, `"origin_host":"evil.test"`),
		"a user service repeating its digest":    withExtraField(vectorUserServicePlanDocument, `"definition_digest":"`+vectorMinimalDigest+`"`),
		"a user service without its slug":        strings.Replace(vectorUserServicePlanDocument, `"definition_slug":"lab-notes",`, "", 1),
		"a user service without its digest":      strings.Replace(vectorUserServicePlanDocument, `"definition_digest":"`+vectorUserServiceDigest+`",`, "", 1),
		"a user service without its image":       strings.Replace(vectorUserServicePlanDocument, `"image_reference":"`+vectorUserImageReference+`",`, "", 1),
		"a user service claiming a private door": strings.Replace(vectorUserServicePlanDocument, `"deploy_user_service"`, `"deploy_private_service"`, 1),
		"a private service claiming the third":   strings.Replace(vectorPrivateServicePlanDocument, `"deploy_private_service"`, `"deploy_user_service"`, 1),
		"a snapshot claiming the third door":     strings.Replace(vectorSnapshotPlanDocument, `"snapshot_service"`, `"deploy_user_service"`, 1),
		"an oversized user service origin":       strings.Replace(vectorUserServicePlanDocument, vectorUserOriginHost, strings.Repeat("a", MaxPlanBytes), 1),

		"an empty document":                       "",
		"two values":                              vectorRoutePlanDocument + "{}",
		"an array of documents":                   "[" + vectorRoutePlanDocument + "]",
		"a truncated document":                    strings.TrimSuffix(vectorRoutePlanDocument, "}"),
		"an oversized document":                   strings.Replace(vectorRoutePlanDocument, vectorRouteHost, strings.Repeat("a", MaxPlanBytes), 1),
		"an oversized service document":           strings.Replace(vectorWebServicePlanDocument, BentoPDFImageReference, strings.Repeat("a", MaxPlanBytes), 1),
		"an oversized origin":                     strings.Replace(vectorPrivateServicePlanDocument, vectorOriginHost, strings.Repeat("a", MaxPlanBytes), 1),
		"an oversized slot":                       strings.Replace(vectorSnapshotPlanDocument, vectorSnapshotSlot, strings.Repeat("a", MaxPlanBytes), 1),
		"a private document repeating its origin": withExtraField(vectorPrivateServicePlanDocument, `"origin_host":"evil.test"`),
		"a snapshot repeating its slot":           withExtraField(vectorSnapshotPlanDocument, `"snapshot_slot":"weekly"`),
		"a document that is only its operation":   `{"operation":"publish_route"}`,
		"a document whose operation is a schema1": `{"operation":"deploy_oci_probe"}`,
	} {
		if _, err := DecodeV2([]byte(document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestSchemaOneAndSchemaTwoRefuseOneAnother keeps the older contract exactly
// where it was.
//
// A probe plan decodes, hashes and freezes as it always did, and neither decoder
// accepts a document of the other schema — the version is not a hint, it selects
// which closed contract the document is held against.
func TestSchemaOneAndSchemaTwoRefuseOneAnother(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"a service plan":         vectorWebServicePlanDocument,
		"an entrypoint plan":     vectorEntrypointPlanDocument,
		"a route plan":           vectorRoutePlanDocument,
		"a private service plan": vectorPrivateServicePlanDocument,
		"a link route plan":      vectorLinkRoutePlanDocument,
		"a snapshot plan":        vectorSnapshotPlanDocument,
		"a restore plan":         vectorRestorePlanDocument,
		"a user service plan":    vectorUserServicePlanDocument,
	} {
		if _, err := Decode([]byte(document)); err == nil {
			t.Fatalf("the schema 1 decoder accepted %s", name)
		}
	}
	if _, err := DecodeV2([]byte(vectorPlanDocument)); err == nil {
		t.Fatal("the schema 2 decoder accepted a probe plan")
	}
	if TranscriptDomain == TranscriptDomainV2 {
		t.Fatal("the two schemas share a transcript domain")
	}
	if SchemaVersion == SchemaVersionV2 {
		t.Fatal("the two schemas share a version")
	}
}

// TestASchemaTwoPlanSurvivesTransportAndReturnsTheSameBytes states the exact
// limit of what a transport may do: reshape the JSON, and only that.
func TestASchemaTwoPlanSurvivesTransportAndReturnsTheSameBytes(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		canonical string
		reshaped  string
		digest    string
	}{
		"web service": {
			canonical: vectorWebServicePlanDocument,
			digest:    vectorWebServicePlanSHA256,
			reshaped: fmt.Sprintf(`{
  "local_port": %d,
  "image_digest": %q,
  "image_reference": %q,
  "service_profile": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, vectorLocalPort, BentoPDFImageDigest, BentoPDFImageReference, vectorServiceProfile,
				OperationDeployWebService, vectorMachine, vectorInfrastructure),
		},
		"entrypoint": {
			canonical: vectorEntrypointPlanDocument,
			digest:    vectorEntrypointPlanSHA256,
			reshaped: fmt.Sprintf(`{
  "image_digest": %q,
  "image_reference": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, EntrypointImageDigest, EntrypointImageReference,
				OperationDeployEntrypoint, vectorMachine, vectorInfrastructure),
		},
		"route": {
			canonical: vectorRoutePlanDocument,
			digest:    vectorRoutePlanSHA256,
			reshaped: fmt.Sprintf(`{
  "backend_port": %d,
  "route_host": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, vectorBackendPort, vectorRouteHost,
				OperationPublishRoute, vectorMachine, vectorInfrastructure),
		},
		"private service": {
			canonical: vectorPrivateServicePlanDocument,
			digest:    vectorPrivateServicePlanSHA256,
			reshaped: fmt.Sprintf(`{
  "origin_host": %q,
  "local_port": %d,
  "image_digest": %q,
  "image_reference": %q,
  "service_profile": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, vectorOriginHost, vectorPrivateLocalPort, VaultwardenImageDigest, VaultwardenImageReference,
				vectorPrivateProfile, OperationDeployPrivateService, vectorMachine, vectorInfrastructure),
		},
		"link route": {
			canonical: vectorLinkRoutePlanDocument,
			digest:    vectorLinkRoutePlanSHA256,
			reshaped: fmt.Sprintf(`{
  "backend_port": %d,
  "route_host": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, vectorLinkBackendPort, vectorLinkRouteHost,
				OperationPublishLinkRoute, vectorMachine, vectorInfrastructure),
		},
		"snapshot": {
			canonical: vectorSnapshotPlanDocument,
			digest:    vectorSnapshotPlanSHA256,
			reshaped: fmt.Sprintf(`{
  "snapshot_slot": %q,
  "service_profile": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, vectorSnapshotSlot, vectorPrivateProfile,
				OperationSnapshotService, vectorMachine, vectorInfrastructure),
		},
		// The rollback of a restore travels like any other document, and it is the
		// one that names the reserved slot: a transport that reshaped it carries
		// the same return, and the Auxiliary decodes it by these very rules.
		"the return itself": {
			canonical: vectorRestoreRollbackDocument,
			digest:    vectorRestoreRollbackSHA256,
			reshaped: fmt.Sprintf(`{
  "snapshot_slot": %q,
  "service_profile": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, ReservedSnapshotSlot, vectorPrivateProfile,
				OperationRestoreService, vectorMachine, vectorInfrastructure),
		},
		"user service": {
			canonical: vectorUserServicePlanDocument,
			digest:    vectorUserServicePlanSHA256,
			reshaped: fmt.Sprintf(`{
  "origin_host": %q,
  "local_port": %d,
  "image_digest": %q,
  "image_reference": %q,
  "definition_digest": %q,
  "definition_slug": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, vectorUserOriginHost, vectorUserLocalPort, vectorUserImageDigest, vectorUserImageReference,
				vectorUserServiceDigest, vectorUserServiceSlug,
				OperationDeployUserService, vectorMachine, vectorInfrastructure),
		},
		// A definition that consumes no origin leaves the field empty, and a
		// transport that drops it altogether carries the same plan: the digest is
		// rebuilt from the fields, and an absent origin and an empty one are one
		// value. That is the same latitude the definition's own empty lists have,
		// and it stops exactly there — the Controller emits one spelling, the one
		// pinned above.
		"user service without an origin": {
			canonical: vectorMinimalUserPlanDocument,
			digest:    vectorMinimalUserPlanSHA256,
			reshaped: fmt.Sprintf(`{
  "local_port": %d,
  "image_digest": %q,
  "image_reference": %q,
  "definition_digest": %q,
  "definition_slug": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, vectorMinimalUserPort, vectorMinimalImageDigest, vectorMinimalReference,
				vectorMinimalDigest, vectorMinimalSlug,
				OperationDeployUserService, vectorMachine, vectorInfrastructure),
		},
	} {
		decoded, err := DecodeV2([]byte(subject.canonical))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		digest, err := decoded.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest != subject.digest {
			t.Fatalf("%s: a decoded plan changed its digest: %s", name, digest)
		}
		reencoded, err := decoded.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(reencoded) != subject.canonical {
			t.Fatalf("%s: re-encoding a decoded plan produced other bytes:\n%s", name, reencoded)
		}

		reordered, err := DecodeV2([]byte(subject.reshaped))
		if err != nil {
			t.Fatalf("%s: a reindented document is the same plan: %v", name, err)
		}
		reorderedDigest, err := reordered.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if reorderedDigest != subject.digest {
			t.Fatalf("%s: reindentation changed the plan digest: %s", name, reorderedDigest)
		}
		reorderedBytes, err := reordered.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(reorderedBytes) != subject.canonical {
			t.Fatalf("%s: a reindented plan did not return to its canonical bytes:\n%s", name, reorderedBytes)
		}
	}
}

// TestTheRollbackOfASchemaTwoPairIsTheOtherPairItself is what makes a rollback a
// plan rather than a promise, in each of the three groups: removal for a
// deployment, redeployment for a removal, retire_route for publish_route.
func TestTheRollbackOfASchemaTwoPairIsTheOtherPairItself(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		forward func() (V2Pair, error)
		reverse func() (V2Pair, error)
	}{
		"web service": {
			forward: func() (V2Pair, error) {
				return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
					vectorMachine, vectorServiceProfile, vectorLocalPort)
			},
			reverse: func() (V2Pair, error) {
				return BuildWebServicePair(OperationRemoveWebService, vectorInfrastructure,
					vectorMachine, vectorServiceProfile, vectorLocalPort)
			},
		},
		"entrypoint": {
			forward: func() (V2Pair, error) {
				return BuildEntrypointPair(OperationDeployEntrypoint, vectorInfrastructure, vectorMachine)
			},
			reverse: func() (V2Pair, error) {
				return BuildEntrypointPair(OperationRemoveEntrypoint, vectorInfrastructure, vectorMachine)
			},
		},
		"route": {
			forward: func() (V2Pair, error) {
				return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
					vectorMachine, vectorRouteHost, vectorBackendPort)
			},
			reverse: func() (V2Pair, error) {
				return BuildRoutePair(OperationRetireRoute, vectorInfrastructure,
					vectorMachine, vectorRouteHost, vectorBackendPort)
			},
		},
		"private service": {
			forward: func() (V2Pair, error) {
				return BuildPrivateServicePair(OperationDeployPrivateService, vectorInfrastructure,
					vectorMachine, vectorPrivateProfile, vectorPrivateLocalPort, vectorOriginHost)
			},
			reverse: func() (V2Pair, error) {
				return BuildPrivateServicePair(OperationRemovePrivateService, vectorInfrastructure,
					vectorMachine, vectorPrivateProfile, vectorPrivateLocalPort, vectorOriginHost)
			},
		},
		"link route": {
			forward: func() (V2Pair, error) {
				return BuildLinkRoutePair(OperationPublishLinkRoute, vectorInfrastructure,
					vectorMachine, vectorLinkRouteHost, vectorLinkBackendPort)
			},
			reverse: func() (V2Pair, error) {
				return BuildLinkRoutePair(OperationRetireLinkRoute, vectorInfrastructure,
					vectorMachine, vectorLinkRouteHost, vectorLinkBackendPort)
			},
		},
		// The archive pair is the one whose second direction the contract calls
		// asymmetric in what it means, and symmetric in what it builds: the
		// rollback of a discard is a snapshot of the same slot, and what that
		// snapshot will archive is the state the machine holds when it runs.
		"user service": {
			forward: func() (V2Pair, error) {
				return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
					vectorMachine, vectorReferenceDefinition(t), vectorUserImageDigest,
					vectorUserLocalPort, vectorUserOriginHost)
			},
			reverse: func() (V2Pair, error) {
				return BuildUserServicePair(OperationRemoveUserService, vectorInfrastructure,
					vectorMachine, vectorReferenceDefinition(t), vectorUserImageDigest,
					vectorUserLocalPort, vectorUserOriginHost)
			},
		},
		// The same pair over a definition that consumes no origin, so that the
		// inversion is proven to leave the conditional field exactly where it was:
		// a removal names the same instance as the deployment it undoes, origin
		// included and origin absent alike.
		"user service without an origin": {
			forward: func() (V2Pair, error) {
				return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
					vectorMachine, vectorMinimalDefinition(t), vectorMinimalImageDigest,
					vectorMinimalUserPort, vectorMinimalUserOrigin)
			},
			reverse: func() (V2Pair, error) {
				return BuildUserServicePair(OperationRemoveUserService, vectorInfrastructure,
					vectorMachine, vectorMinimalDefinition(t), vectorMinimalImageDigest,
					vectorMinimalUserPort, vectorMinimalUserOrigin)
			},
		},
		"snapshot": {
			forward: func() (V2Pair, error) {
				return BuildSnapshotPair(OperationSnapshotService, vectorInfrastructure,
					vectorMachine, vectorPrivateProfile, vectorSnapshotSlot)
			},
			reverse: func() (V2Pair, error) {
				return BuildSnapshotPair(OperationDiscardSnapshot, vectorInfrastructure,
					vectorMachine, vectorPrivateProfile, vectorSnapshotSlot)
			},
		},
	} {
		forward, err := subject.forward()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		reverse, err := subject.reverse()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		frozenForward, err := forward.Freeze()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		frozenReverse, err := reverse.Freeze()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if frozenForward.RollbackSHA256 != frozenReverse.PlanSHA256 {
			t.Fatalf("%s: the rollback of a plan is not the other direction of the same instance", name)
		}
		if frozenReverse.RollbackSHA256 != frozenForward.PlanSHA256 {
			t.Fatalf("%s: the two directions do not undo one another", name)
		}
		if !bytes.Equal(frozenForward.RollbackDocument, frozenReverse.PlanDocument) ||
			!bytes.Equal(frozenReverse.RollbackDocument, frozenForward.PlanDocument) {
			t.Fatalf("%s: the two directions do not carry the same documents", name)
		}
		if frozenForward.PlanSHA256 == frozenForward.RollbackSHA256 {
			t.Fatalf("%s: a plan and its rollback must not be the same document", name)
		}
		if !forward.Rollback.IsExactInverseOf(forward.Plan) || !forward.Plan.IsExactInverseOf(forward.Rollback) {
			t.Fatalf("%s: undoing is not symmetric between the two documents of a pair", name)
		}
		if forward.Plan.IsExactInverseOf(forward.Plan) {
			t.Fatalf("%s: a plan was read as undoing itself", name)
		}
		if forward.Rollback.IsExactInverseOf(nil) {
			t.Fatalf("%s: an absent plan was read as undone", name)
		}
		if forward.Plan.Target() != (Target{InfrastructureID: vectorInfrastructure, MachineID: vectorMachine}) {
			t.Fatalf("%s: a plan names another target than the one it was built for", name)
		}
		if forward.Rollback.Target() != forward.Plan.Target() {
			t.Fatalf("%s: a rollback aims at another machine than the plan it undoes", name)
		}
	}
}

// TestARollbackOfSchemaTwoIsRecognisedOnlyWhenItUndoesExactlyThePlan is what a
// machine asks before acting: the document it was handed as an undoing has to be
// one it could apply to return to the state it is about to leave.
func TestARollbackOfSchemaTwoIsRecognisedOnlyWhenItUndoesExactlyThePlan(t *testing.T) {
	t.Parallel()
	service, err := BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
		vectorMachine, vectorServiceProfile, vectorLocalPort)
	if err != nil {
		t.Fatal(err)
	}
	route, err := BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
		vectorMachine, vectorRouteHost, vectorBackendPort)
	if err != nil {
		t.Fatal(err)
	}
	entrypoint, err := BuildEntrypointPair(OperationDeployEntrypoint, vectorInfrastructure, vectorMachine)
	if err != nil {
		t.Fatal(err)
	}

	// A document of another operation group is never an undoing, whatever it
	// names: the two are not the same plan written differently.
	if route.Rollback.IsExactInverseOf(service.Plan) || service.Rollback.IsExactInverseOf(route.Plan) {
		t.Fatal("a document of another operation group was read as an undoing")
	}
	if entrypoint.Rollback.IsExactInverseOf(service.Plan) {
		t.Fatal("an entrypoint removal was read as undoing a service deployment")
	}

	for name, forge := range map[string]func(*WebServiceDocument){
		"another machine":        func(d *WebServiceDocument) { d.MachineID = "lab-machine-2" },
		"another infrastructure": func(d *WebServiceDocument) { d.InfrastructureID = otherInfrastructure },
		"another port":           func(d *WebServiceDocument) { d.LocalPort = vectorLocalPort + 1 },
		"another profile":        func(d *WebServiceDocument) { d.ServiceProfile = "bentopdf-simple" },
		"another image":          func(d *WebServiceDocument) { d.ImageReference = EntrypointImageReference },
		"another digest":         func(d *WebServiceDocument) { d.ImageDigest = otherPinnedDigest },
		"the same operation":     func(d *WebServiceDocument) { d.Operation = OperationDeployWebService },
		"an unknown operation":   func(d *WebServiceDocument) { d.Operation = "install_container" },
	} {
		forged, ok := service.Rollback.(WebServiceDocument)
		if !ok {
			t.Fatal("the rollback of a service pair is not a service document")
		}
		forge(&forged)
		if forged.IsExactInverseOf(service.Plan) {
			t.Fatalf("a rollback naming %s was read as undoing the plan", name)
		}
	}

	for name, forge := range map[string]func(*RouteDocument){
		"another host":         func(d *RouteDocument) { d.RouteHost = "other.lab.your-cloud.test" },
		"another backend port": func(d *RouteDocument) { d.BackendPort = vectorBackendPort + 1 },
		"the same operation":   func(d *RouteDocument) { d.Operation = OperationPublishRoute },
		"an unknown operation": func(d *RouteDocument) { d.Operation = "publish_ingress" },
	} {
		forged, ok := route.Rollback.(RouteDocument)
		if !ok {
			t.Fatal("the rollback of a route pair is not a route document")
		}
		forge(&forged)
		if forged.IsExactInverseOf(route.Plan) {
			t.Fatalf("a rollback naming %s was read as undoing the route", name)
		}
	}
}

// TestTheRollbackOfARestoreIsARestoreOfTheReservedSlot is the one rollback shape
// of this schema that a reader could not guess from the operation table.
//
// A restore is undone by another restore, because the flow writes the state it is
// about to replace into the reserved slot before replacing anything. The
// returning document is therefore complete, readable and deterministic like every
// other rollback of the product — and it is the only document that names that
// slot. The forward direction cannot: a restore of the reserved slot would undo
// itself, and a pair whose two halves are one document is not a pair.
func TestTheRollbackOfARestoreIsARestoreOfTheReservedSlot(t *testing.T) {
	t.Parallel()
	pair, err := BuildRestorePair(vectorInfrastructure, vectorMachine,
		vectorPrivateProfile, vectorSnapshotSlot)
	if err != nil {
		t.Fatal(err)
	}
	rollback, isRestore := pair.Rollback.(RestoreDocument)
	if !isRestore {
		t.Fatalf("the rollback of a restore is a %T", pair.Rollback)
	}
	if rollback.Operation != OperationRestoreService {
		t.Fatalf("the rollback of a restore names %q", rollback.Operation)
	}
	if rollback.SnapshotSlot != ReservedSnapshotSlot {
		t.Fatalf("the rollback of a restore names slot %q", rollback.SnapshotSlot)
	}
	subject, isRestore := pair.Plan.(RestoreDocument)
	if !isRestore || subject.SnapshotSlot != vectorSnapshotSlot {
		t.Fatalf("the plan of a restore pair is not the restore that was asked for: %+v", pair.Plan)
	}
	if !pair.Rollback.IsExactInverseOf(pair.Plan) {
		t.Fatal("the rollback of a restore is not read as undoing it")
	}
	if pair.Plan.IsExactInverseOf(pair.Rollback) {
		t.Fatal("a restore of a named slot was read as undoing the return itself")
	}

	// The reserved slot is refused as a forward direction whichever way it is
	// asked for, and the pair a builder cannot freeze is a pair that does not
	// exist rather than one whose two documents are the same bytes.
	if _, err := BuildRestorePair(vectorInfrastructure, vectorMachine,
		vectorPrivateProfile, ReservedSnapshotSlot); err == nil {
		t.Fatal("a restore of the reserved slot was built as a forward plan")
	}
	if _, err := buildV2Pair(rollback); err == nil {
		t.Fatal("a document that undoes itself was frozen as a pair")
	}

	// The archive operations may not name it at all, in either direction: the
	// slot belongs to the mechanism, and a plan that wrote over it or destroyed it
	// would remove the possibility of returning.
	for _, operation := range []string{OperationSnapshotService, OperationDiscardSnapshot} {
		if _, err := BuildSnapshotPair(operation, vectorInfrastructure, vectorMachine,
			vectorPrivateProfile, ReservedSnapshotSlot); err == nil {
			t.Fatalf("%s named the reserved slot", operation)
		}
	}
}

func TestSchemaTwoBuildersRefuseEveryInstanceOutsideTheContract(t *testing.T) {
	t.Parallel()
	for _, port := range []int{MinLocalPort, MaxLocalPort} {
		if _, err := BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
			vectorMachine, vectorServiceProfile, port); err != nil {
			t.Fatalf("the bound %d of the port range must build: %v", port, err)
		}
	}
	if _, err := BuildRoutePair(OperationRetireRoute, vectorInfrastructure,
		vectorMachine, "abc", MinBackendPort); err != nil {
		t.Fatalf("the bounds of the route contract must build: %v", err)
	}

	for name, build := range map[string]func() (V2Pair, error){
		"a service pair on an unknown operation": func() (V2Pair, error) {
			return BuildWebServicePair("install_container", vectorInfrastructure,
				vectorMachine, vectorServiceProfile, vectorLocalPort)
		},
		"a service pair on the probe operation": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployOCIProbe, vectorInfrastructure,
				vectorMachine, vectorServiceProfile, vectorLocalPort)
		},
		"a service pair on a route operation": func() (V2Pair, error) {
			return BuildWebServicePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, vectorServiceProfile, vectorLocalPort)
		},
		"a service pair on an unknown profile": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
				vectorMachine, "bentopdf-simple", vectorLocalPort)
		},
		"a service pair without a profile": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
				vectorMachine, "", vectorLocalPort)
		},
		"a service pair on a privileged port": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
				vectorMachine, vectorServiceProfile, 443)
		},
		"a service pair on a malformed machine": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
				"LAB", vectorServiceProfile, vectorLocalPort)
		},
		"a service pair on a malformed infrastructure": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, "not-a-uuid",
				vectorMachine, vectorServiceProfile, vectorLocalPort)
		},
		"an entrypoint pair on a service operation": func() (V2Pair, error) {
			return BuildEntrypointPair(OperationDeployWebService, vectorInfrastructure, vectorMachine)
		},
		"an entrypoint pair on the read-only operation of the previous palier": func() (V2Pair, error) {
			return BuildEntrypointPair("diagnose_protocol_read_only", vectorInfrastructure, vectorMachine)
		},
		"an entrypoint pair without an operation": func() (V2Pair, error) {
			return BuildEntrypointPair("", vectorInfrastructure, vectorMachine)
		},
		"a route pair on an entrypoint operation": func() (V2Pair, error) {
			return BuildRoutePair(OperationDeployEntrypoint, vectorInfrastructure,
				vectorMachine, vectorRouteHost, vectorBackendPort)
		},
		"a route pair on a wildcard host": func() (V2Pair, error) {
			return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, "*.lab.your-cloud.test", vectorBackendPort)
		},
		"a route pair without a host": func() (V2Pair, error) {
			return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, "", vectorBackendPort)
		},
		"a route pair on a privileged backend": func() (V2Pair, error) {
			return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, vectorRouteHost, 443)
		},
		"a route pair beyond the backend range": func() (V2Pair, error) {
			return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, vectorRouteHost, MaxBackendPort+1)
		},
		"a private pair on the stateless profile": func() (V2Pair, error) {
			return BuildPrivateServicePair(OperationDeployPrivateService, vectorInfrastructure,
				vectorMachine, ServiceProfileBentoPDF, vectorPrivateLocalPort, vectorOriginHost)
		},
		"a stateless pair on the private profile": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
				vectorMachine, ServiceProfileVaultwarden, vectorLocalPort)
		},
		"a private pair on a stateless operation": func() (V2Pair, error) {
			return BuildPrivateServicePair(OperationDeployWebService, vectorInfrastructure,
				vectorMachine, vectorPrivateProfile, vectorPrivateLocalPort, vectorOriginHost)
		},
		"a private pair without an origin": func() (V2Pair, error) {
			return BuildPrivateServicePair(OperationDeployPrivateService, vectorInfrastructure,
				vectorMachine, vectorPrivateProfile, vectorPrivateLocalPort, "")
		},
		"a private pair on a wildcard origin": func() (V2Pair, error) {
			return BuildPrivateServicePair(OperationDeployPrivateService, vectorInfrastructure,
				vectorMachine, vectorPrivateProfile, vectorPrivateLocalPort, "*.lab.your-cloud.test")
		},
		"a private pair on a privileged port": func() (V2Pair, error) {
			return BuildPrivateServicePair(OperationDeployPrivateService, vectorInfrastructure,
				vectorMachine, vectorPrivateProfile, 443, vectorOriginHost)
		},
		"a link route pair on a public route operation": func() (V2Pair, error) {
			return BuildLinkRoutePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, vectorLinkRouteHost, vectorLinkBackendPort)
		},
		"a link route pair on a wildcard host": func() (V2Pair, error) {
			return BuildLinkRoutePair(OperationPublishLinkRoute, vectorInfrastructure,
				vectorMachine, "*.lab.your-cloud.test", vectorLinkBackendPort)
		},
		"a link route pair on a privileged backend": func() (V2Pair, error) {
			return BuildLinkRoutePair(OperationPublishLinkRoute, vectorInfrastructure,
				vectorMachine, vectorLinkRouteHost, 443)
		},
		"a snapshot pair on the stateless profile": func() (V2Pair, error) {
			return BuildSnapshotPair(OperationSnapshotService, vectorInfrastructure,
				vectorMachine, ServiceProfileBentoPDF, vectorSnapshotSlot)
		},
		"a snapshot pair on a restore operation": func() (V2Pair, error) {
			return BuildSnapshotPair(OperationRestoreService, vectorInfrastructure,
				vectorMachine, vectorPrivateProfile, vectorSnapshotSlot)
		},
		"a snapshot pair without a slot": func() (V2Pair, error) {
			return BuildSnapshotPair(OperationSnapshotService, vectorInfrastructure,
				vectorMachine, vectorPrivateProfile, "")
		},
		"a snapshot pair on a traversal slot": func() (V2Pair, error) {
			return BuildSnapshotPair(OperationSnapshotService, vectorInfrastructure,
				vectorMachine, vectorPrivateProfile, "../../etc/shadow")
		},
		"a snapshot pair on an oversized slot": func() (V2Pair, error) {
			return BuildSnapshotPair(OperationSnapshotService, vectorInfrastructure,
				vectorMachine, vectorPrivateProfile, strings.Repeat("a", MaxSnapshotSlotBytes+1))
		},
		"a restore pair on the stateless profile": func() (V2Pair, error) {
			return BuildRestorePair(vectorInfrastructure, vectorMachine,
				ServiceProfileBentoPDF, vectorSnapshotSlot)
		},
		"a restore pair on an upper-case slot": func() (V2Pair, error) {
			return BuildRestorePair(vectorInfrastructure, vectorMachine,
				vectorPrivateProfile, "Nightly")
		},
		"a restore pair on a malformed machine": func() (V2Pair, error) {
			return BuildRestorePair(vectorInfrastructure, "LAB", vectorPrivateProfile, vectorSnapshotSlot)
		},
		"an archive pair on a name no slug could be": func() (V2Pair, error) {
			return BuildSnapshotPair(OperationSnapshotService, vectorInfrastructure,
				vectorMachine, "vaultwarden-lite-2", vectorSnapshotSlot)
		},
		"a restore pair on a reserved name": func() (V2Pair, error) {
			return BuildRestorePair(vectorInfrastructure, vectorMachine, "entrypoint", vectorSnapshotSlot)
		},
		"a user pair on a stateless operation": func() (V2Pair, error) {
			return BuildUserServicePair(OperationDeployWebService, vectorInfrastructure,
				vectorMachine, vectorReferenceDefinition(t), vectorUserImageDigest,
				vectorUserLocalPort, vectorUserOriginHost)
		},
		"a user pair on a private operation": func() (V2Pair, error) {
			return BuildUserServicePair(OperationDeployPrivateService, vectorInfrastructure,
				vectorMachine, vectorReferenceDefinition(t), vectorUserImageDigest,
				vectorUserLocalPort, vectorUserOriginHost)
		},
		"a user pair on an unknown operation": func() (V2Pair, error) {
			return BuildUserServicePair("start_user_service", vectorInfrastructure,
				vectorMachine, vectorReferenceDefinition(t), vectorUserImageDigest,
				vectorUserLocalPort, vectorUserOriginHost)
		},
		"a user pair on a definition outside its own contract": func() (V2Pair, error) {
			return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
				vectorMachine, servicedefinition.Document{}, vectorUserImageDigest,
				vectorUserLocalPort, vectorUserOriginHost)
		},
		"a user pair on a malformed image digest": func() (V2Pair, error) {
			return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
				vectorMachine, vectorReferenceDefinition(t), "sha256:not-a-digest",
				vectorUserLocalPort, vectorUserOriginHost)
		},
		"a user pair without an image digest": func() (V2Pair, error) {
			return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
				vectorMachine, vectorReferenceDefinition(t), "",
				vectorUserLocalPort, vectorUserOriginHost)
		},
		"a user pair on a privileged port": func() (V2Pair, error) {
			return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
				vectorMachine, vectorReferenceDefinition(t), vectorUserImageDigest,
				443, vectorUserOriginHost)
		},
		// The two directions of the conditional field, at the one place the rule
		// can be held: an origin an interpolating definition needs and the caller
		// left out, and an origin a definition consumes nowhere.
		"a user pair without the origin its definition interpolates": func() (V2Pair, error) {
			return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
				vectorMachine, vectorReferenceDefinition(t), vectorUserImageDigest,
				vectorUserLocalPort, "")
		},
		"a user pair carrying an origin its definition consumes nowhere": func() (V2Pair, error) {
			return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
				vectorMachine, vectorMinimalDefinition(t), vectorMinimalImageDigest,
				vectorMinimalUserPort, vectorUserOriginHost)
		},
		"a user pair on a wildcard origin": func() (V2Pair, error) {
			return BuildUserServicePair(OperationDeployUserService, vectorInfrastructure,
				vectorMachine, vectorReferenceDefinition(t), vectorUserImageDigest,
				vectorUserLocalPort, "*.lab.your-cloud.test")
		},
	} {
		if _, err := build(); err == nil {
			t.Fatalf("%s built a pair", name)
		}
	}

	// An empty pair freezes nothing rather than freezing a zero document.
	if _, err := (V2Pair{}).Freeze(); err == nil {
		t.Fatal("an empty pair was frozen")
	}
}

// TestTheImagesOfThisPalierArePinnedByDigestAlone keeps the decisions of the
// contract testable rather than merely written: one profile, one image per
// pinned role, no second truth beside a digest, and an undoing for every
// operation.
//
// The human versions of these images — the tags a release note names — appear
// nowhere in this package on purpose. A tag in the source would be a second,
// movable identity beside the digest, and the digest is the identity.
func TestTheImagesOfThisPalierArePinnedByDigestAlone(t *testing.T) {
	t.Parallel()
	for name, reference := range map[string]string{
		"the service image":    BentoPDFImageReference,
		"the entrypoint image": EntrypointImageReference,
		"the private image":    VaultwardenImageReference,
	} {
		if strings.ContainsAny(reference, ":@") {
			t.Fatalf("%s carries a tag or a digest: %s", name, reference)
		}
		if !strings.Contains(reference, "/") {
			t.Fatalf("%s names no registry: %s", name, reference)
		}
	}
	digests := map[string]string{
		"the service digest":    BentoPDFImageDigest,
		"the entrypoint digest": EntrypointImageDigest,
		"the private digest":    VaultwardenImageDigest,
	}
	seen := map[string]string{}
	for name, digest := range digests {
		if !canonicalOCIDigest.MatchString(digest) {
			t.Fatalf("%s is not canonical: %s", name, digest)
		}
		if other, collision := seen[digest]; collision {
			t.Fatalf("%s and %s pin the same image", name, other)
		}
		seen[digest] = name
	}

	// The two doors hold one profile each, and neither list holds the other's.
	// That is the whole of the cross-refusal: it is a lookup that fails rather
	// than a comparison someone has to remember to write.
	if len(profileImage) != 1 || len(privateProfileImage) != 1 {
		t.Fatalf("this palier describes one profile per door, not %d and %d",
			len(profileImage), len(privateProfileImage))
	}
	if _, known := profileImage[ServiceProfileBentoPDF]; !known {
		t.Fatal("the stateless profile of this palier is not the one it names")
	}
	if _, known := privateProfileImage[ServiceProfileVaultwarden]; !known {
		t.Fatal("the private profile of this palier is not the one it names")
	}
	if _, crossed := profileImage[ServiceProfileVaultwarden]; crossed {
		t.Fatal("the data-bearing profile is described by the stateless door")
	}
	if _, crossed := privateProfileImage[ServiceProfileBentoPDF]; crossed {
		t.Fatal("the stateless profile is described by the private door")
	}

	// The third door pins no image at all, and that is a decision rather than an
	// omission: the repository is the definition's and the digest is the
	// instance's, so a table here would be a third authority over a value the
	// product does not own.
	if _, pinned := profileImage[vectorUserServiceSlug]; pinned {
		t.Fatal("a definition's slug is described by the stateless door")
	}
	if _, pinned := privateProfileImage[vectorUserServiceSlug]; pinned {
		t.Fatal("a definition's slug is described by the private door")
	}

	if len(inverseOperationV2) != 15 || len(operationGroups) != 15 {
		t.Fatalf("schema 2 describes exactly fifteen operations, not %d and %d",
			len(inverseOperationV2), len(operationGroups))
	}
	for operation, inverse := range inverseOperationV2 {
		if inverseOperationV2[inverse] != operation {
			t.Fatalf("operation %q is not undone by an operation that redoes it", operation)
		}
		if operationGroups[operation] == 0 {
			t.Fatalf("operation %q carries no closed field list", operation)
		}
		if operationGroups[inverse] != operationGroups[operation] {
			t.Fatalf("operation %q and its undoing do not carry the same fields", operation)
		}
		// Exactly one operation of this schema is undone by itself, and it is the
		// return: what changes between a restore and its undoing is the slot. Any
		// second self-inverse entry would be an operation whose pair is one
		// document, which buildV2Pair refuses to freeze.
		if inverse == operation && operation != OperationRestoreService {
			t.Fatalf("operation %q is its own undoing", operation)
		}
	}
	if _, borrowed := operationGroups[OperationDeployOCIProbe]; borrowed {
		t.Fatal("a schema 1 operation carries a schema 2 field list")
	}
	if _, borrowed := operationGroups[OperationPrepareLink]; borrowed {
		t.Fatal("a schema 3 operation carries a schema 2 field list")
	}
}
