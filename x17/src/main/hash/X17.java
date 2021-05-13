package hash;

import crypto.Digest;

/**
 * This implements the X17 Hash algorithm
 *
 * @author Orbsynated
 * @version v1.0.1
 */
public class X17 extends X17Core {

  public X17() {}

  /**
   * Get the natural hash function output length (in bytes).
   *
   * @return the digest output length (in bytes)
   */
  @Override
  public int getDigestLength() {
    return 64;
  }

  /**
   * Clone the current state. The returned object evolves independantly of this object.
   *
   * @return the clone
   */
  @Override
  public Digest copy() {
    return copyState(new X17());
  }
}
