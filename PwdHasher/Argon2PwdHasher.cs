using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace PwdHasher;

public class Argon2PwdHasher : IPwdHasher {
    readonly Argon2id _alg = null!;
    readonly String _parmMark;

    const Int32 _saltSize = 16;
    const Int32 _hashLength = 32;

    public Argon2PwdHasher(Int32 memoryCost = 64 * 1024, Int32 timeCost = 4) {
        _alg = PasswordBasedKeyDerivationAlgorithm.Argon2id(new Argon2Parameters() {
            MemorySize = memoryCost,
            NumberOfPasses = timeCost,
            DegreeOfParallelism = 1,
        });
        _parmMark = $"m{memoryCost}t{timeCost}p1";
    }

    static Argon2id _GetArgon2IdFromParmMark(String parmMark) {
        var t = parmMark.IndexOf('t');
        var p = parmMark.IndexOf('p');

        return PasswordBasedKeyDerivationAlgorithm.Argon2id(new Argon2Parameters() {
            MemorySize = Convert.ToInt32(parmMark[1..t]),
            NumberOfPasses = Convert.ToInt32(parmMark[(t + 1)..p]),
            DegreeOfParallelism = 1,
        });
    }

    String _HashPassword(Argon2id alg, String password, Byte[] salt) {
        var bytes = alg.DeriveBytes(
            Encoding.UTF8.GetBytes(password),
            salt,
            _hashLength);

        var s = new StringBuilder()
            .Append(_parmMark)
            .Append('$')
            .Append(Convert.ToBase64String(salt))
            .Append('$')
            .Append(Convert.ToBase64String(bytes));

        return s.ToString();
    }

    public String HashPassword(String password) {
        return _HashPassword(_alg, password, RandomNumberGenerator.GetBytes(_saltSize));
    }

    public VerificationResult VerifyHashedPassword(String hashedPassword, String providedPassword) {
        var pwdGroup = hashedPassword.Split('$');

        var needRefresh = pwdGroup[0] != _parmMark;
        var alg = !needRefresh ? _alg : _GetArgon2IdFromParmMark(pwdGroup[0]);

        var targetHash = _HashPassword(alg, providedPassword, Convert.FromBase64String(pwdGroup[1]));
        if (targetHash != hashedPassword) {
            return VerificationResult.Failed;
        }

        return needRefresh
            ? VerificationResult.SuccessRehashNeeded
            : VerificationResult.Success;
    }
}
