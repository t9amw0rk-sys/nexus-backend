using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NexusBackend.Data;
using NexusBackend.DTOs;
using NexusBackend.Models;

namespace NexusBackend.Services;

public interface IAuthService
{
    Task<AuthResponseDTO> RegisterAsync(RegisterDTO dto);
    Task<AuthResponseDTO> LoginAsync(LoginDTO dto);
    Task<AuthResponseDTO> RefreshTokenAsync(string refreshToken);
    Task LogoutAsync(string refreshToken);
    Task<AppUser> FindOrCreateGoogleUserAsync(string email, string fullName);
    Task<AuthResponseDTO> GenerateTokensForUserAsync(AppUser user);
}

public class AuthService : IAuthService
{
    private readonly UserManager<AppUser> _userManager;
    private readonly AppDbContext _context;
    private readonly ITokenService _tokenService;
    private readonly IConfiguration _config;

    public AuthService(UserManager<AppUser> userManager, AppDbContext context,
        ITokenService tokenService, IConfiguration config)
    {
        _userManager = userManager;
        _context = context;
        _tokenService = tokenService;
        _config = config;
    }

    public async Task<AuthResponseDTO> RegisterAsync(RegisterDTO dto)
    {
        var existingUser = await _userManager.FindByEmailAsync(dto.Email);
        if (existingUser != null)
            throw new ArgumentException("Email already exists.");

        var user = new AppUser
        {
            FullName = dto.FullName,
            Email = dto.Email,
            UserName = dto.Email,
            IsActive = true,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
            throw new ArgumentException(string.Join(", ", result.Errors.Select(e => e.Description)));

        await _userManager.AddToRoleAsync(user, "User");

        return await GenerateAuthResponse(user);
    }

    public async Task<AuthResponseDTO> LoginAsync(LoginDTO dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
            throw new UnauthorizedAccessException("Invalid email or password.");

        if (!user.IsActive)
            throw new UnauthorizedAccessException("Your account has been deactivated.");

        return await GenerateAuthResponse(user);
    }

    public async Task<AuthResponseDTO> RefreshTokenAsync(string refreshToken)
    {
        var token = await _context.RefreshTokens
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.Token == refreshToken);

        if (token == null || !token.IsActive)
            throw new UnauthorizedAccessException("Invalid or expired refresh token.");

        token.IsRevoked = true;
        await _context.SaveChangesAsync();

        return await GenerateAuthResponse(token.User);
    }

    public async Task LogoutAsync(string refreshToken)
    {
        var token = await _context.RefreshTokens
            .FirstOrDefaultAsync(r => r.Token == refreshToken);

        if (token != null)
        {
            token.IsRevoked = true;
            await _context.SaveChangesAsync();
        }
    }

    public async Task<AppUser> FindOrCreateGoogleUserAsync(string email, string fullName)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
            return user;

        user = new AppUser
        {
            FullName = fullName,
            Email = email,
            UserName = email,
            IsActive = true,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user);
        if (!result.Succeeded)
            throw new ArgumentException(string.Join(", ", result.Errors.Select(e => e.Description)));

        await _userManager.AddToRoleAsync(user, "User");
        return user;
    }

    public async Task<AuthResponseDTO> GenerateTokensForUserAsync(AppUser user)
    {
        return await GenerateAuthResponse(user);
    }

    private async Task<AuthResponseDTO> GenerateAuthResponse(AppUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);
        var accessToken = _tokenService.GenerateAccessToken(user, roles);
        var refreshToken = _tokenService.GenerateRefreshToken();

        var refreshTokenDays = int.Parse(_config["JwtSettings:RefreshTokenExpiryDays"]!);

        var oldTokens = await _context.RefreshTokens
            .Where(r => r.UserId == user.Id && !r.IsRevoked)
            .ToListAsync();
        if (oldTokens.Any())
            _context.RefreshTokens.RemoveRange(oldTokens);

        _context.RefreshTokens.Add(new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(refreshTokenDays)
        });

        await _context.SaveChangesAsync();

        return new AuthResponseDTO
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            User = new UserDTO
            {
                Id = user.Id,
                FullName = user.FullName,
                Email = user.Email!,
                AvatarUrl = user.AvatarUrl,
                Role = roles.FirstOrDefault() ?? "User",
                CreatedAt = user.CreatedAt
            }
        };
    }
}