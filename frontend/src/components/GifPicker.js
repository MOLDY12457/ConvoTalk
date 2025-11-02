import React, { useState, useEffect } from 'react';
import { Input } from './ui/input';
import { Button } from './ui/button';
import { Search, Loader2 } from 'lucide-react';
import { ScrollArea } from './ui/scroll-area';

const GifPicker = ({ onGifSelect }) => {
  const [gifs, setGifs] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Tenor API key - in production, this should be in environment variables
  const TENOR_API_KEY = 'AIzaSyDx_YlG9aNdSFWfv_d7spdWalE3MbKWWRY'; // Demo key

  useEffect(() => {
    // Load trending GIFs on mount
    fetchTrendingGifs();
  }, []);

  const fetchTrendingGifs = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(
        `https://tenor.googleapis.com/v2/featured?key=${TENOR_API_KEY}&client_key=convotalk&limit=20&contentfilter=medium`
      );
      
      if (!response.ok) {
        throw new Error('Erreur lors du chargement des GIFs');
      }
      
      const data = await response.json();
      setGifs(data.results || []);
    } catch (err) {
      console.error('Erreur Tenor API:', err);
      setError('Impossible de charger les GIFs');
      // Fallback with demo GIFs
      setGifs([]);
    } finally {
      setLoading(false);
    }
  };

  const searchGifs = async (query) => {
    if (!query.trim()) {
      fetchTrendingGifs();
      return;
    }

    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(
        `https://tenor.googleapis.com/v2/search?key=${TENOR_API_KEY}&client_key=convotalk&q=${encodeURIComponent(query)}&limit=20&contentfilter=medium`
      );
      
      if (!response.ok) {
        throw new Error('Erreur de recherche');
      }
      
      const data = await response.json();
      setGifs(data.results || []);
    } catch (err) {
      console.error('Erreur recherche GIF:', err);
      setError('Erreur lors de la recherche');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    searchGifs(searchTerm);
  };

  const handleGifClick = (gif) => {
    // Get the medium quality GIF URL
    const gifUrl = gif.media_formats?.gif?.url || gif.media_formats?.mediumgif?.url || gif.url;
    onGifSelect(gifUrl);
  };

  return (
    <div className="w-full h-96" data-testid="gif-picker">
      {/* Search */}
      <form onSubmit={handleSearch} className="flex space-x-2 mb-4">
        <Input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Rechercher des GIFs..."
          className="bg-gray-700 border-gray-600 text-white"
        />
        <Button type="submit" variant="outline" className="border-gray-600">
          <Search size={16} />
        </Button>
      </form>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center h-32">
          <Loader2 className="animate-spin text-purple-500" size={32} />
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="text-center py-8">
          <p className="text-red-400 mb-4">{error}</p>
          <Button onClick={fetchTrendingGifs} variant="outline">
            Réessayer
          </Button>
        </div>
      )}

      {/* GIFs Grid */}
      {!loading && !error && (
        <ScrollArea className="h-full">
          {gifs.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-gray-400">Aucun GIF trouvé</p>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-2">
              {gifs.map((gif) => (
                <button
                  key={gif.id}
                  onClick={() => handleGifClick(gif)}
                  className="relative group overflow-hidden rounded-lg bg-gray-700 hover:bg-gray-600 transition-colors"
                  data-testid={`gif-${gif.id}`}
                >
                  <img
                    src={gif.media_formats?.tinygif?.url || gif.media_formats?.gif?.url}
                    alt={gif.content_description || 'GIF'}
                    className="w-full h-24 object-cover"
                    loading="lazy"
                  />
                  <div className="absolute inset-0 bg-black/30 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                    <span className="text-white text-xs font-medium">Cliquez pour sélectionner</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </ScrollArea>
      )}

      {/* Demo GIFs fallback when Tenor API fails */}
      {!loading && gifs.length === 0 && !error && (
        <div className="grid grid-cols-2 gap-2">
          {[...Array(6)].map((_, index) => (
            <button
              key={index}
              onClick={() => onGifSelect(`https://via.placeholder.com/200x150/7c3aed/ffffff?text=GIF+${index + 1}`)}
              className="relative group overflow-hidden rounded-lg bg-gray-700 hover:bg-gray-600 transition-colors"
            >
              <div className="w-full h-24 bg-gradient-to-br from-purple-600 to-pink-600 flex items-center justify-center">
                <span className="text-white font-medium">GIF {index + 1}</span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

export default GifPicker;