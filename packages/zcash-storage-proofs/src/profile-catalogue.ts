// Generated from profiles/catalogue.v1.json. Run `npm run catalogue`.
export const PROFILE_CATALOGUE = {
  "schemaVersion": 1,
  "protocol": {
    "pool": "ironwood-v3",
    "era": "nu6.3",
    "networks": [
      "mainnet",
      "testnet"
    ]
  },
  "toolchain": {
    "noirCommit": "5a7ee9bf5ed8973076df7bb0d2b723024db09ae7",
    "aztecCommit": "0219f11d8133970df3974fe5ae65e006bf8c193a",
    "aztecLabsCommit": "d2e67c1d938f06a6476dd7d4bd01e73771923dd1",
    "bignumCommit": "78ed0df23307a9a6be7af68f09fca6a3d6a1b34e",
    "bigcurveCommit": "f9af3d8892db14c5f57d01e712455c1d6d9336f1"
  },
  "privateFormat": {
    "flavor": "MegaApp",
    "maximumDomain": 16777216
  },
  "profiles": [
    {
      "id": "contents-ordinary-v1",
      "claim": "note-contents-membership",
      "generationKind": "copy",
      "sourcePackage": "examples/aztec_contents/contract",
      "hintTransport": "ordinary",
      "capacities": null,
      "blockCount": "none",
      "transactionVersions": [],
      "selectable": false,
      "validation": {
        "status": "stale-source",
        "sourceGraphSha256": "457e0fb94f38ff65d443b314b9c35d2fc6dff1a829b284cee2ad49a54d4d7770",
        "toolchainPinSha256": "a7fab744464be107a5ac31e42e794b112207ab12e8b572c76ae13cff17ee33eb",
        "artifactSha256": "8fc30f32662ba5d3555c184195ca347d2960da05a274eca737cfd891bdc028bb",
        "artifactInterfaceSha256": "d1a758ea35b3438f67b3b65c891700d01e5234264e21c23ad9635e286771bf4b",
        "functions": [
          {
            "name": "verify",
            "bytecodeSha256": "651b0a572648fd778e232d16c54ea271f2149f905308b56c84d66fe41cc0a883",
            "gates": 1445734,
            "flavor": "MegaApp"
          }
        ],
        "evidence": [],
        "proofVerified": false,
        "kernelVerified": false,
        "scope": "Prior finalized gates checked with the pinned final-v6 bb_check. Exact padded domain is unmeasured with a supported provider. The consolidated source requires fresh compilation and private constraint validation before release or automatic selection. No proof or checkpoint authentication is implied.",
        "checkerSha256": "0214894c54ef8ba28a6f1c99d189adf7ea07917d3cb4446dc85a12122ce605b9"
      },
      "verificationKey": null
    },
    {
      "id": "contents-native-v1",
      "claim": "note-contents-membership",
      "generationKind": "copy",
      "sourcePackage": "examples/aztec_contents_capsules/contract",
      "hintTransport": "capsule",
      "capacities": null,
      "blockCount": "none",
      "transactionVersions": [],
      "selectable": false,
      "validation": {
        "status": "stale-source",
        "sourceGraphSha256": "57bfd85a63a4c07df692875c98da86d03ea623ffcb34fa59626e9683129244e0",
        "toolchainPinSha256": "a7fab744464be107a5ac31e42e794b112207ab12e8b572c76ae13cff17ee33eb",
        "artifactSha256": "c439cf0e96c191ec75bce04c4ea7e08a17a12808331c5f16d2751c32ce886230",
        "artifactInterfaceSha256": "0ba49f6cfcffbd9c757a4bc09149ae9a130b69eb979343521631da5705ee135a",
        "functions": [
          {
            "name": "verify",
            "bytecodeSha256": "57692407f3e860e899068f72136348cc45a3b093bd18a26360af4926c6757705",
            "gates": 1461670,
            "flavor": "MegaApp"
          }
        ],
        "evidence": [],
        "proofVerified": false,
        "kernelVerified": false,
        "scope": "Prior finalized gates checked with the pinned final-v6 bb_check. Exact padded domain is unmeasured with a supported provider. The consolidated source requires fresh compilation and private constraint validation before release or automatic selection. No proof or checkpoint authentication is implied.",
        "checkerSha256": "0214894c54ef8ba28a6f1c99d189adf7ea07917d3cb4446dc85a12122ce605b9"
      },
      "verificationKey": null
    },
    {
      "id": "nullifier-absence-1b-4t-2a-0r-v1",
      "claim": "nullifier-absence-from-activation",
      "generationKind": "nullifier-absence",
      "sourcePackage": "examples/aztec_nullifier_absence/contract",
      "hintTransport": "ordinary",
      "capacities": {
        "blocks": 1,
        "transactionsPerBlock": 4,
        "actionsPerTransaction": 2,
        "legacyBytesPerTransaction": 0
      },
      "blockCount": "exact",
      "transactionVersions": [
        5,
        6
      ],
      "selectable": false,
      "validation": {
        "status": "stale-source",
        "sourceGraphSha256": "7088b8e891b280100e5ad9d99e19a074e4751e7b64d04fbc636b5381d0831429",
        "toolchainPinSha256": "a7fab744464be107a5ac31e42e794b112207ab12e8b572c76ae13cff17ee33eb",
        "artifactSha256": "843ad8fe8be3e19e60906fa535a37b339161c7853b1a0ad03db9462dc4b1c71d",
        "artifactInterfaceSha256": "50239b857b9230fc0f25839be6a418b420efb85a3d46ef8eaca3915e43c5ba67",
        "functions": [
          {
            "name": "verify",
            "bytecodeSha256": "2fb555bd4966366001c8e7fb849d9e3eab415b330ff97980487e4cb7255e7447",
            "gates": 432373,
            "flavor": "MegaApp"
          }
        ],
        "evidence": [],
        "proofVerified": false,
        "kernelVerified": false,
        "scope": "Prior finalized gates checked with the pinned final-v6 bb_check. Exact padded domain is unmeasured with a supported provider. The consolidated source requires fresh compilation and private constraint validation before release or automatic selection. No proof or checkpoint authentication is implied.",
        "checkerSha256": "0214894c54ef8ba28a6f1c99d189adf7ea07917d3cb4446dc85a12122ce605b9"
      },
      "verificationKey": null
    },
    {
      "id": "nullifier-absence-2b-4t-2a-0r-v1",
      "claim": "nullifier-absence-from-activation",
      "generationKind": "nullifier-absence",
      "sourcePackage": "examples/aztec_nullifier_absence/contract",
      "hintTransport": "ordinary",
      "capacities": {
        "blocks": 2,
        "transactionsPerBlock": 4,
        "actionsPerTransaction": 2,
        "legacyBytesPerTransaction": 0
      },
      "blockCount": "exact",
      "transactionVersions": [
        5,
        6
      ],
      "selectable": false,
      "validation": {
        "status": "stale-source",
        "sourceGraphSha256": "9ef28d406ccd6493aae7c538cfc9063563020f9f38d3773ca7d26e75b0aa5b58",
        "toolchainPinSha256": "a7fab744464be107a5ac31e42e794b112207ab12e8b572c76ae13cff17ee33eb",
        "artifactSha256": "490b68c512a9f919e1e712b7a890dd0e5fb4ee33b97e44cc62988677ef28c6d6",
        "artifactInterfaceSha256": "776545a62065248d29bf47d2c0ea0e5687c741328cd0d924a0cd10e5d1812b6b",
        "functions": [
          {
            "name": "verify",
            "bytecodeSha256": "8e0a10ec6a5806e808c09eb1ba592605585846ccd31ef2f5844e27cdc3594704",
            "gates": 855916,
            "flavor": "MegaApp"
          }
        ],
        "evidence": [],
        "proofVerified": false,
        "kernelVerified": false,
        "scope": "Prior finalized gates checked with the pinned final-v6 bb_check. Exact padded domain is unmeasured with a supported provider. The consolidated source requires fresh compilation and private constraint validation before release or automatic selection. No proof or checkpoint authentication is implied.",
        "checkerSha256": "0214894c54ef8ba28a6f1c99d189adf7ea07917d3cb4446dc85a12122ce605b9"
      },
      "verificationKey": null
    },
    {
      "id": "nullifier-absence-2b-4t-2a-256r-v1",
      "claim": "nullifier-absence-from-activation",
      "generationKind": "nullifier-absence",
      "sourcePackage": "examples/aztec_nullifier_absence/contract",
      "hintTransport": "ordinary",
      "capacities": {
        "blocks": 2,
        "transactionsPerBlock": 4,
        "actionsPerTransaction": 2,
        "legacyBytesPerTransaction": 256
      },
      "blockCount": "exact",
      "transactionVersions": [
        4,
        5,
        6
      ],
      "selectable": false,
      "validation": {
        "status": "stale-source",
        "sourceGraphSha256": "c406f51ac55ca7289e589605a2f6d72a99dc13699badc0f829a9a49ac8f9b5f1",
        "toolchainPinSha256": "a7fab744464be107a5ac31e42e794b112207ab12e8b572c76ae13cff17ee33eb",
        "artifactSha256": "f05f9649c105a82fe0d590e918484136990160cb31cb92ea3acf7252d76ce494",
        "artifactInterfaceSha256": "65101f70a62013717f9dfbb99eb7aae76251e7faffb601e896a56c6bb8ec311a",
        "functions": [
          {
            "name": "verify",
            "bytecodeSha256": "2e19feeb564d6ba7a2a3c5e29a9671bc0d4da32411349c3082731074401d9005",
            "gates": 1112445,
            "flavor": "MegaApp"
          }
        ],
        "evidence": [],
        "proofVerified": false,
        "kernelVerified": false,
        "scope": "Prior finalized gates checked with the pinned final-v6 bb_check. Exact padded domain is unmeasured with a supported provider. The consolidated source requires fresh compilation and private constraint validation before release or automatic selection. No proof or checkpoint authentication is implied.",
        "checkerSha256": "0214894c54ef8ba28a6f1c99d189adf7ea07917d3cb4446dc85a12122ce605b9"
      },
      "verificationKey": null
    },
    {
      "id": "nullifier-absence-2b-8t-4a-1024r-v1",
      "claim": "nullifier-absence-from-activation",
      "generationKind": "nullifier-absence",
      "sourcePackage": "examples/aztec_nullifier_absence/contract",
      "hintTransport": "ordinary",
      "capacities": {
        "blocks": 2,
        "transactionsPerBlock": 8,
        "actionsPerTransaction": 4,
        "legacyBytesPerTransaction": 1024
      },
      "blockCount": "exact",
      "transactionVersions": [
        4,
        5,
        6
      ],
      "selectable": false,
      "validation": {
        "status": "stale-source",
        "sourceGraphSha256": "d48cc1a33f8bc4f5b4a50b0385c8bbf176e7d97dc6cf768fb3cae3ad65af6f58",
        "toolchainPinSha256": "a7fab744464be107a5ac31e42e794b112207ab12e8b572c76ae13cff17ee33eb",
        "artifactSha256": "467ef640bd9d31875df861127810129cc27fda609d02b451ae5020a79e029eae",
        "artifactInterfaceSha256": "ad1f2486f08f3840e16ab1003cd8b229d994c36020b8fba9b033a0ce6e1e3316",
        "functions": [
          {
            "name": "verify",
            "bytecodeSha256": "97d1e435df639981bc8137e8bbd1dada6fae689727520e1badf0149eb074d321",
            "gates": 3359549,
            "flavor": "MegaApp"
          }
        ],
        "evidence": [],
        "proofVerified": false,
        "kernelVerified": false,
        "scope": "Prior finalized gates checked with the pinned final-v6 bb_check. Exact padded domain is unmeasured with a supported provider. The consolidated source requires fresh compilation and private constraint validation before release or automatic selection. No proof or checkpoint authentication is implied.",
        "checkerSha256": "0214894c54ef8ba28a6f1c99d189adf7ea07917d3cb4446dc85a12122ce605b9"
      },
      "verificationKey": null
    },
    {
      "id": "nullifier-absence-state-2b-4t-2a-256r-v1",
      "claim": "authenticated-nullifier-nullifier-absence-state",
      "generationKind": "nullifier-absence-state",
      "sourcePackage": "examples/nullifier_absence_state/contract",
      "hintTransport": "ordinary",
      "capacities": {
        "blocks": 2,
        "transactionsPerBlock": 4,
        "actionsPerTransaction": 2,
        "legacyBytesPerTransaction": 256
      },
      "blockCount": "up-to",
      "transactionVersions": [
        4,
        5,
        6
      ],
      "selectable": false,
      "validation": {
        "status": "pending",
        "evidence": [],
        "functions": []
      },
      "verificationKey": null
    }
  ]
} as const;
