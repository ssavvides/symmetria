
<img src="resources/logo/logo-name.png" alt="Symmetria" width="600">

The _symmetria_ system introduces two _symmetric encryption_ schemes namely
**SAHE (symmetric Additive Homomorphic Encryption)** and
**SMHE (symmetric Multiplicative Homomorphic Encryption)**
that allow additions and multiplications over encrypted data.

These schemes can replace previous asymmetric PHE schemes such as Paillier or ElGamal. _symmetria_ leads
to smaller ciphertext size overheads and faster execution times for homomorphic operations.

## Installation

You can compile this repository by running:

```bash
mvn package
```

This will create the jar file `target/symmetria-0.1-SNAPSHOT.jar`

`mvn package` will automatically run the `junit` tests provided.

You can avoid running tests during compilation by running:

```bash
mvn package -DskipTests
```

## Usage
To run a class in the above jar use:

```bash
java -cp target/symmetria-0.1-SNAPSHOT.jar CLASS_FULL_PATH
```

## Examples
To compare SAHE to Paillier you can run:

```bash
java -cp target/symmetria-0.1-SNAPSHOT.jar edu.purdue.symmetria.evaluate.AHEScheme
```

and to compare SMHE to ElGamal:

```bash
java -cp target/symmetria-0.1-SNAPSHOT.jar edu.purdue.symmetria.evaluate.MHEScheme
```

To run "Packed Paillier" which packs 21 plaintexts in a single ciphertext using the packing method described in the paper "T. Ge and S. Zdonik. Answering aggregation queries in system model, VLDB'07" you can run:

```bash
java -cp target/symmetria-0.1-SNAPSHOT.jar edu.purdue.symmetria.evaluate.PackedScheme
```

## Contact
If you want to know more about our project or have questions, please contact
Savvas <savvas@purdue.edu>.
