import {DeployFunction} from "hardhat-deploy/types";
import {HardhatRuntimeEnvironment} from "hardhat/types";

const GUARDIANS = [
];

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const {deployer} = await hre.getNamedAccounts();
  const {deploy} = hre.deployments;


  const deployedSecretSocialRecovery = await deploy("SecretSocialRecovery", {
    from: deployer,
    log: true,
    args: [GUARDIANS, 2, deployer],
  });

  console.log(`SecretSocialRecovery contract: `, deployedSecretSocialRecovery.address);
};
export default func;
func.id = "deploy_secret_social_recovery"; // id required to prevent reexecution
func.tags = ["SecretSocialRecovery"];
