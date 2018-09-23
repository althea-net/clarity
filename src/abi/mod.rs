pub mod contract;
pub mod operation;

use abi::contract::Contract;
use abi::operation::Operation;

/// The JSON format for a contract’s interface is given by an array of
/// function and/or event descriptions. A function description is a
/// JSON object with the fields
struct Item {}

// impl Contract {
//     fn read<T: io::Read>(reader: T) -> Result<Self, Error> {

//     }
// }

// [
// 	{
// 		"constant": true,
// 		"inputs": [
// 			{
// 				"name": "",
// 				"type": "bytes"
// 			},
// 			{
// 				"name": "",
// 				"type": "bool"
// 			},
// 			{
// 				"name": "",
// 				"type": "uint256[]"
// 			}
// 		],
// 		"name": "sam",
// 		"outputs": [],
// 		"payable": false,
// 		"stateMutability": "pure",
// 		"type": "function"
// 	},
// 	{
// 		"constant": true,
// 		"inputs": [
// 			{
// 				"name": "x",
// 				"type": "uint32"
// 			},
// 			{
// 				"name": "y",
// 				"type": "bool"
// 			}
// 		],
// 		"name": "baz",
// 		"outputs": [
// 			{
// 				"name": "r",
// 				"type": "bool"
// 			}
// 		],
// 		"payable": false,
// 		"stateMutability": "pure",
// 		"type": "function"
// 	},
// 	{
// 		"constant": true,
// 		"inputs": [
// 			{
// 				"name": "",
// 				"type": "bytes3[2]"
// 			}
// 		],
// 		"name": "bar",
// 		"outputs": [],
// 		"payable": false,
// 		"stateMutability": "pure",
// 		"type": "function"
// 	}
// ]
