namespace PwdHasher;

public interface IPwdHasher {
    String HashPassword(String password);
    VerificationResult VerifyHashedPassword(String hashedPassword, String providedPassword);
}
