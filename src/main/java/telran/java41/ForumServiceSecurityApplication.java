package telran.java41;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCrypt;

import telran.java41.accounting.dao.UserAccountRepository;
import telran.java41.accounting.model.UserAccount;

@SpringBootApplication
public class ForumServiceSecurityApplication{// implements CommandLineRunner {

	UserAccountRepository userAccountRepository;

	public static void main(String[] args) {
		SpringApplication.run(ForumServiceSecurityApplication.class, args);
	}

//	@Override
//	public void run(String... args) throws Exception {
//		if (!userAccountRepository.existsById("admin")) {
//			String password = BCrypt.hashpw("admin", BCrypt.gensalt());
//			UserAccount userAccount = new UserAccount("admin", password, "", "");
//			userAccount.addRole("MODERATOR");
//			userAccount.addRole("ADMINISTRATOR");
//			userAccountRepository.save(userAccount);
//		}
//	}

}
